"""This module implements the TFTP Server functionality. Instantiate an
instance of the server, and then run the listen() method to listen for client
requests. Logging is performed via a standard logging object set in
TftpShared."""

import sys
import socket, os, time
import select
import threading
import logging
import struct

LOG_LEVEL = logging.NOTSET
MIN_BLKSIZE = 8
DEF_BLKSIZE = 512
MAX_BLKSIZE = 65536
SOCK_TIMEOUT = 5
MAX_DUPS = 20
TIMEOUT_RETRIES = 5
DEF_TFTP_PORT = 69

# A hook for deliberately introducing delay in testing.
DELAY_BLOCK = 0

# Initialize the logger.
logging.basicConfig()
# The logger used by this library. Feel free to clobber it with your own, if you like, as
# long as it conforms to Python's logging.
log = logging.getLogger('tftpy')


def tftpassert(condition, msg):
    """This function is a simple utility that will check the condition
    passed for a false state. If it finds one, it throws a TftpException
    with the message passed. This just makes the code throughout cleaner
    by refactoring."""
    if not condition:
        raise TftpException, msg


def setLogLevel(level):
    """This function is a utility function for setting the internal log level.
    The log level defaults to logging.NOTSET, so unwanted output to stdout is
    not created."""
    global log
    log.setLevel(level)


class TftpErrors(object):
    """This class is a convenience for defining the common tftp error codes,
    and making them more readable in the code."""
    NotDefined = 0
    FileNotFound = 1
    AccessViolation = 2
    DiskFull = 3
    IllegalTftpOp = 4
    UnknownTID = 5
    FileAlreadyExists = 6
    NoSuchUser = 7
    FailedNegotiation = 8


class TftpException(Exception):
    """This class is the parent class of all exceptions regarding the handling
    of the TFTP protocol."""
    pass


class TftpTimeout(TftpException):
    """This class represents a timeout error waiting for a response from the
    other end."""
    pass


class TftpPacketFactory(object):
    """This class generates TftpPacket objects. It is responsible for parsing
    raw buffers off of the wire and returning objects representing them, via
    the parse() method."""

    def __init__(self):
        self.classes = {
            1: TftpPacketRRQ,
            2: TftpPacketWRQ,
            3: TftpPacketDAT,
            4: TftpPacketACK,
            5: TftpPacketERR,
            6: TftpPacketOACK
        }

    def parse(self, buffer):
        """This method is used to parse an existing datagram into its
        corresponding TftpPacket object. The buffer is the raw bytes off of
        the network."""
        log.debug("parsing a %d byte packet", len(buffer))
        (opcode,) = struct.unpack("!H", buffer[:2])
        log.debug("opcode is %d", opcode)
        packet = self.__create(opcode)
        packet.buffer = buffer
        return packet.decode()

    def __create(self, opcode):
        """This method returns the appropriate class object corresponding to
        the passed opcode."""
        tftpassert(self.classes.has_key(opcode),
                   "Unsupported opcode: %d" % opcode)

        packet = self.classes[opcode]()

        return packet


class TftpMetrics(object):
    """A class representing metrics of the transfer."""

    def __init__(self):
        # Bytes transferred
        self.bytes = 0
        # Bytes re-sent
        self.resent_bytes = 0
        # Duplicate packets received
        self.dups = {}
        self.dupcount = 0
        # Times
        self.start_time = 0
        self.end_time = 0
        self.duration = 0
        # Rates
        self.bps = 0
        self.kbps = 0
        # Generic errors
        self.errors = 0

    def compute(self):
        # Compute transfer time
        self.duration = self.end_time - self.start_time
        if self.duration == 0:
            self.duration = 1
        log.debug("TftpMetrics.compute: duration is %s", self.duration)
        self.bps = (self.bytes * 8.0) / self.duration
        self.kbps = self.bps / 1024.0
        log.debug("TftpMetrics.compute: kbps is %s", self.kbps)
        for key in self.dups:
            self.dupcount += self.dups[key]

    def add_dup(self, pkt):
        """This method adds a dup for a packet to the metrics."""
        log.debug("Recording a dup of %s", pkt)
        s = str(pkt)
        if self.dups.has_key(s):
            self.dups[s] += 1
        else:
            self.dups[s] = 1
        tftpassert(self.dups[s] < MAX_DUPS, "Max duplicates reached")


class TftpState(object):
    """The base class for the states."""

    def __init__(self, context):
        """Constructor for setting up common instance variables. The involved
        file object is required, since in tftp there's always a file
        involved."""
        self.context = context

    def handle(self, pkt, raddress, rport):
        """An abstract method for handling a packet. It is expected to return
        a TftpState object, either itself or a new state."""
        raise NotImplementedError, "Abstract method"

    def handleOACK(self, pkt):
        """This method handles an OACK from the server, syncing any accepted
        options."""
        if pkt.options.keys() > 0:
            if pkt.match_options(self.context.options):
                log.info("Successful negotiation of options")
                # Set options to OACK options
                self.context.options = pkt.options
                for key in self.context.options:
                    log.info("    %s = %s" % (key, self.context.options[key]))
            else:
                log.error("Failed to negotiate options")
                raise TftpException, "Failed to negotiate options"
        else:
            raise TftpException, "No options found in OACK"

    def returnSupportedOptions(self, options):
        """This method takes a requested options list from a client, and
        returns the ones that are supported."""
        # We support the options blksize and tsize right now.
        # FIXME - put this somewhere else?
        accepted_options = {}
        for option in options:
            if option == 'blksize':
                # Make sure it's valid.
                if int(options[option]) > MAX_BLKSIZE:
                    log.info("Client requested blksize greater than %d "
                             "setting to maximum" % MAX_BLKSIZE)
                    accepted_options[option] = MAX_BLKSIZE
                elif int(options[option]) < MIN_BLKSIZE:
                    log.info("Client requested blksize less than %d "
                             "setting to minimum" % MIN_BLKSIZE)
                    accepted_options[option] = MIN_BLKSIZE
                else:
                    accepted_options[option] = options[option]
            elif option == 'tsize':
                log.debug("tsize option is set")
                accepted_options['tsize'] = 1
            else:
                log.info("Dropping unsupported option '%s'" % option)
        log.debug("Returning these accepted options: %s", accepted_options)
        return accepted_options

    def sendDAT(self):
        """This method sends the next DAT packet based on the data in the
        context. It returns a boolean indicating whether the transfer is
        finished."""
        finished = False
        blocknumber = self.context.next_block
        # Test hook
        if DELAY_BLOCK and DELAY_BLOCK == blocknumber:
            import time
            log.debug("Deliberately delaying 10 seconds...")
            time.sleep(10)
        dat = None
        blksize = self.context.getBlocksize()
        buffer = self.context.fileobj.read(blksize)
        log.debug("Read %d bytes into buffer", len(buffer))
        if len(buffer) < blksize:
            log.info("Reached EOF on file %s"
                     % self.context.file_to_transfer)
            finished = True
        dat = TftpPacketDAT()
        dat.data = buffer
        dat.blocknumber = blocknumber
        self.context.metrics.bytes += len(dat.data)
        log.debug("Sending DAT packet %d", dat.blocknumber)
        self.context.sock.sendto(dat.encode().buffer,
                                 (self.context.host, self.context.tidport))
        if self.context.packethook:
            self.context.packethook(dat)
        self.context.last_pkt = dat
        return finished

    def sendACK(self, blocknumber=None):
        """This method sends an ack packet to the block number specified. If
        none is specified, it defaults to the next_block property in the
        parent context."""
        log.debug("In sendACK, passed blocknumber is %s", blocknumber)
        if blocknumber is None:
            blocknumber = self.context.next_block
        log.info("Sending ack to block %d" % blocknumber)
        ackpkt = TftpPacketACK()
        ackpkt.blocknumber = blocknumber
        self.context.sock.sendto(ackpkt.encode().buffer,
                                 (self.context.host,
                                  self.context.tidport))
        self.context.last_pkt = ackpkt

    def sendError(self, errorcode):
        """This method uses the socket passed, and uses the errorcode to
        compose and send an error packet."""
        log.debug("In sendError, being asked to send error %d", errorcode)
        errpkt = TftpPacketERR()
        errpkt.errorcode = errorcode
        self.context.sock.sendto(errpkt.encode().buffer,
                                 (self.context.host,
                                  self.context.tidport))
        self.context.last_pkt = errpkt

    def sendOACK(self):
        """This method sends an OACK packet with the options from the current
        context."""
        log.debug("In sendOACK with options %s", self.context.options)
        pkt = TftpPacketOACK()
        pkt.options = self.context.options
        self.context.sock.sendto(pkt.encode().buffer,
                                 (self.context.host,
                                  self.context.tidport))
        self.context.last_pkt = pkt

    def resendLast(self):
        "Resend the last sent packet due to a timeout."
        log.warn("Resending packet %s on sessions %s"
                 % (self.context.last_pkt, self))
        self.context.metrics.resent_bytes += len(self.context.last_pkt.buffer)
        self.context.metrics.add_dup(self.context.last_pkt)
        sendto_port = self.context.tidport
        if not sendto_port:
            # If the tidport wasn't set, then the remote end hasn't even
            # started talking to us yet. That's not good. Maybe it's not
            # there.
            sendto_port = self.context.port
        self.context.sock.sendto(self.context.last_pkt.encode().buffer,
                                 (self.context.host, sendto_port))
        if self.context.packethook:
            self.context.packethook(self.context.last_pkt)

    def handleDat(self, pkt):
        """This method handles a DAT packet during a client download, or a
        server upload."""
        log.info("Handling DAT packet - block %d" % pkt.blocknumber)
        log.debug("Expecting block %s", self.context.next_block)
        if pkt.blocknumber == self.context.next_block:
            log.debug("Good, received block %d in sequence", pkt.blocknumber)

            self.sendACK()
            self.context.next_block += 1

            log.debug("Writing %d bytes to output file", len(pkt.data))
            self.context.fileobj.write(pkt.data)
            self.context.metrics.bytes += len(pkt.data)
            # Check for end-of-file, any less than full data packet.
            if len(pkt.data) < self.context.getBlocksize():
                log.info("End of file detected")
                return None

        elif pkt.blocknumber < self.context.next_block:
            if pkt.blocknumber == 0:
                log.warn("There is no block zero!")
                self.sendError(TftpErrors.IllegalTftpOp)
                raise TftpException, "There is no block zero!"
            log.warn("Dropping duplicate block %d" % pkt.blocknumber)
            self.context.metrics.add_dup(pkt)
            log.debug("ACKing block %d again, just in case", pkt.blocknumber)
            self.sendACK(pkt.blocknumber)

        else:
            # FIXME: should we be more tolerant and just discard instead?
            msg = "Whoa! Received future block %d but expected %d" \
                  % (pkt.blocknumber, self.context.next_block)
            log.error(msg)
            raise TftpException, msg

        # Default is to ack
        return TftpStateExpectDAT(self.context)


class TftpServerState(TftpState):
    """The base class for server states."""

    def __init__(self, context):
        TftpState.__init__(self, context)

        # This variable is used to store the absolute path to the file being
        # managed.
        self.full_path = None

    def serverInitial(self, pkt, raddress, rport):
        """This method performs initial setup for a server context transfer,
        put here to refactor code out of the TftpStateServerRecvRRQ and
        TftpStateServerRecvWRQ classes, since their initial setup is
        identical. The method returns a boolean, sendoack, to indicate whether
        it is required to send an OACK to the client."""
        options = pkt.options
        sendoack = False
        if not self.context.tidport:
            self.context.tidport = rport
            log.info("Setting tidport to %s" % rport)

        log.debug("Setting default options, blksize")
        self.context.options = {'blksize': DEF_BLKSIZE}

        if options:
            log.debug("Options requested: %s", options)
            supported_options = self.returnSupportedOptions(options)
            self.context.options.update(supported_options)
            sendoack = True

        # FIXME - only octet mode is supported at this time.
        if pkt.mode != 'octet':
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, \
                "Only octet transfers are supported at this time."

        # test host/port of client end
        if self.context.host != raddress or self.context.port != rport:
            self.sendError(TftpErrors.UnknownTID)
            log.error("Expected traffic from %s:%s but received it "
                      "from %s:%s instead."
                      % (self.context.host,
                         self.context.port,
                         raddress,
                         rport))
            # FIXME: increment an error count?
            # Return same state, we're still waiting for valid traffic.
            return self

        log.debug("Requested filename is %s", pkt.filename)

        # Build the filename on this server and ensure it is contained
        # in the specified root directory.
        #
        # Filenames that begin with server root are accepted. It's
        # assumed the client and server are tightly connected and this
        # provides backwards compatibility.
        #
        # Filenames otherwise are relative to the server root. If they
        # begin with a '/' strip it off as otherwise os.path.join will
        # treat it as absolute (regardless of whether it is ntpath or
        # posixpath module
        if pkt.filename.startswith(self.context.root):
            full_path = pkt.filename
        else:
            full_path = os.path.join(
                self.context.root, pkt.filename.lstrip('/'))

        # Use abspath to eliminate any remaining relative elements
        # (e.g. '..') and ensure that is still within the server's
        # root directory
        self.full_path = os.path.abspath(full_path)
        log.debug("full_path is %s", full_path)
        if self.full_path.startswith(self.context.root):
            log.info("requested file is in the server root - good")
        else:
            log.warn("requested file is not within the server root - bad")
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "bad file path"

        self.context.file_to_transfer = pkt.filename

        return sendoack


class TftpStateServerRecvRRQ(TftpServerState):
    """This class represents the state of the TFTP server when it has just
    received an RRQ packet."""

    def handle(self, pkt, raddress, rport):
        "Handle an initial RRQ packet as a server."
        log.debug("In TftpStateServerRecvRRQ.handle")
        sendoack = self.serverInitial(pkt, raddress, rport)
        path = self.full_path
        log.info("Opening file %s for reading" % path)
        if os.path.exists(path):
            # Note: Open in binary mode for win32 portability, since win32
            # blows.
            self.context.fileobj = open(path, "rb")
        elif self.context.dyn_file_func:
            log.debug("No such file %s but using dyn_file_func", path)
            self.context.fileobj = \
                self.context.dyn_file_func(self.context.file_to_transfer)

            if self.context.fileobj is None:
                log.debug("dyn_file_func returned 'None', treating as "
                          "FileNotFound")
                self.sendError(TftpErrors.FileNotFound)
                raise TftpException, "File not found: %s" % path
        else:
            self.sendError(TftpErrors.FileNotFound)
            raise TftpException, "File not found: %s" % path

        # Options negotiation.
        if sendoack:
            # Note, next_block is 0 here since that's the proper
            # acknowledgement to an OACK.
            # FIXME: perhaps we do need a TftpStateExpectOACK class...
            self.sendOACK()
            # Note, self.context.next_block is already 0.
        else:
            self.context.next_block = 1
            log.debug("No requested options, starting send...")
            self.context.pending_complete = self.sendDAT()
        # Note, we expect an ack regardless of whether we sent a DAT or an
        # OACK.
        return TftpStateExpectACK(self.context)

        # Note, we don't have to check any other states in this method, that's
        # up to the caller.


class TftpStateServerRecvWRQ(TftpServerState):
    """This class represents the state of the TFTP server when it has just
    received a WRQ packet."""

    def make_subdirs(self):
        """The purpose of this method is to, if necessary, create all of the
        subdirectories leading up to the file to the written."""
        # Pull off everything below the root.
        subpath = self.full_path[len(self.context.root):]
        log.debug("make_subdirs: subpath is %s", subpath)
        # Split on directory separators, but drop the last one, as it should
        # be the filename.
        dirs = subpath.split(os.sep)[:-1]
        log.debug("dirs is %s", dirs)
        current = self.context.root
        for dir in dirs:
            if dir:
                current = os.path.join(current, dir)
                if os.path.isdir(current):
                    log.debug("%s is already an existing directory", current)
                else:
                    os.mkdir(current, 0700)

    def handle(self, pkt, raddress, rport):
        "Handle an initial WRQ packet as a server."
        log.debug("In TftpStateServerRecvWRQ.handle")
        sendoack = self.serverInitial(pkt, raddress, rport)
        path = self.full_path
        log.info("Opening file %s for writing" % path)
        if os.path.exists(path):
            # FIXME: correct behavior?
            log.warn("File %s exists already, overwriting..." % self.context.file_to_transfer)
        # FIXME: I think we should upload to a temp file and not overwrite the
        # existing file until the file is successfully uploaded.
        self.make_subdirs()
        self.context.fileobj = open(path, "wb")

        # Options negotiation.
        if sendoack:
            log.debug("Sending OACK to client")
            self.sendOACK()
        else:
            log.debug("No requested options, expecting transfer to begin...")
            self.sendACK()
        # Whether we're sending an oack or not, we're expecting a DAT for
        # block 1
        self.context.next_block = 1
        # We may have sent an OACK, but we're expecting a DAT as the response
        # to either the OACK or an ACK, so lets unconditionally use the
        # TftpStateExpectDAT state.
        return TftpStateExpectDAT(self.context)

        # Note, we don't have to check any other states in this method, that's
        # up to the caller.


class TftpStateServerStart(TftpState):
    """The start state for the server. This is a transitory state since at
    this point we don't know if we're handling an upload or a download. We
    will commit to one of them once we interpret the initial packet."""

    def handle(self, pkt, raddress, rport):
        """Handle a packet we just received."""
        log.debug("In TftpStateServerStart.handle")
        if isinstance(pkt, TftpPacketRRQ):
            log.debug("Handling an RRQ packet")
            return TftpStateServerRecvRRQ(self.context).handle(pkt,
                                                               raddress,
                                                               rport)
        elif isinstance(pkt, TftpPacketWRQ):
            log.debug("Handling a WRQ packet")
            return TftpStateServerRecvWRQ(self.context).handle(pkt,
                                                               raddress,
                                                               rport)
        else:
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, \
                "Invalid packet to begin up/download: %s" % pkt


class TftpStateExpectACK(TftpState):
    """This class represents the state of the transfer when a DAT was just
    sent, and we are waiting for an ACK from the server. This class is the
    same one used by the client during the upload, and the server during the
    download."""

    def handle(self, pkt, raddress, rport):
        "Handle a packet, hopefully an ACK since we just sent a DAT."
        if isinstance(pkt, TftpPacketACK):
            log.info("Received ACK for packet %d" % pkt.blocknumber)
            # Is this an ack to the one we just sent?
            if self.context.next_block == pkt.blocknumber:
                if self.context.pending_complete:
                    log.info("Received ACK to final DAT, we're done.")
                    return None
                else:
                    log.debug("Good ACK, sending next DAT")
                    self.context.next_block += 1
                    log.debug("Incremented next_block to %d",
                              self.context.next_block)
                    self.context.pending_complete = self.sendDAT()

            elif pkt.blocknumber < self.context.next_block:
                log.warn("Received duplicate ACK for block %d"
                         % pkt.blocknumber)
                self.context.metrics.add_dup(pkt)

            else:
                log.warn("Oooh, time warp. Received ACK to packet we "
                         "didn't send yet. Discarding.")
                self.context.metrics.errors += 1
            return self
        elif isinstance(pkt, TftpPacketERR):
            log.error("Received ERR packet from peer: %s" % str(pkt))
            raise TftpException, \
                "Received ERR packet from peer: %s" % str(pkt)
        else:
            log.warn("Discarding unsupported packet: %s" % str(pkt))
            return self


class TftpStateExpectDAT(TftpState):
    """Just sent an ACK packet. Waiting for DAT."""

    def handle(self, pkt, raddress, rport):
        """Handle the packet in response to an ACK, which should be a DAT."""
        if isinstance(pkt, TftpPacketDAT):
            return self.handleDat(pkt)

        # Every other packet type is a problem.
        elif isinstance(pkt, TftpPacketACK):
            # Umm, we ACK, you don't.
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received ACK from peer when expecting DAT"

        elif isinstance(pkt, TftpPacketWRQ):
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received WRQ from peer when expecting DAT"

        elif isinstance(pkt, TftpPacketERR):
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received ERR from peer: " + str(pkt)

        else:
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received unknown packet type from peer: " + str(pkt)


class TftpStateSentWRQ(TftpState):
    """Just sent an WRQ packet for an upload."""

    def handle(self, pkt, raddress, rport):
        """Handle a packet we just received."""
        if not self.context.tidport:
            self.context.tidport = rport
            log.debug("Set remote port for session to %s", rport)

        # If we're going to successfully transfer the file, then we should see
        # either an OACK for accepted options, or an ACK to ignore options.
        if isinstance(pkt, TftpPacketOACK):
            log.info("Received OACK from server")
            try:
                self.handleOACK(pkt)
            except TftpException:
                log.error("Failed to negotiate options")
                self.sendError(TftpErrors.FailedNegotiation)
                raise
            else:
                log.debug("Sending first DAT packet")
                self.context.pending_complete = self.sendDAT()
                log.debug("Changing state to TftpStateExpectACK")
                return TftpStateExpectACK(self.context)

        elif isinstance(pkt, TftpPacketACK):
            log.info("Received ACK from server")
            log.debug("Apparently the server ignored our options")
            # The block number should be zero.
            if pkt.blocknumber == 0:
                log.debug("Ack blocknumber is zero as expected")
                log.debug("Sending first DAT packet")
                self.context.pending_complete = self.sendDAT()
                log.debug("Changing state to TftpStateExpectACK")
                return TftpStateExpectACK(self.context)
            else:
                log.warn("Discarding ACK to block %s" % pkt.blocknumber)
                log.debug("Still waiting for valid response from server")
                return self

        elif isinstance(pkt, TftpPacketERR):
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received ERR from server: " + str(pkt)

        elif isinstance(pkt, TftpPacketRRQ):
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received RRQ from server while in upload"

        elif isinstance(pkt, TftpPacketDAT):
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received DAT from server while in upload"

        else:
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received unknown packet type from server: " + str(pkt)

        # By default, no state change.
        return self


class TftpStateSentRRQ(TftpState):
    """Just sent an RRQ packet."""

    def handle(self, pkt, raddress, rport):
        """Handle the packet in response to an RRQ to the server."""
        if not self.context.tidport:
            self.context.tidport = rport
            log.info("Set remote port for session to %s" % rport)

        # Now check the packet type and dispatch it properly.
        if isinstance(pkt, TftpPacketOACK):
            log.info("Received OACK from server")
            try:
                self.handleOACK(pkt)
            except TftpException, err:
                log.error("Failed to negotiate options: %s" % str(err))
                self.sendError(TftpErrors.FailedNegotiation)
                raise
            else:
                log.debug("Sending ACK to OACK")

                self.sendACK(blocknumber=0)

                log.debug("Changing state to TftpStateExpectDAT")
                return TftpStateExpectDAT(self.context)

        elif isinstance(pkt, TftpPacketDAT):
            # If there are any options set, then the server didn't honour any
            # of them.
            log.info("Received DAT from server")
            if self.context.options:
                log.info("Server ignored options, falling back to defaults")
                self.context.options = {'blksize': DEF_BLKSIZE}
            return self.handleDat(pkt)

        # Every other packet type is a problem.
        elif isinstance(pkt, TftpPacketACK):
            # Umm, we ACK, the server doesn't.
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received ACK from server while in download"

        elif isinstance(pkt, TftpPacketWRQ):
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received WRQ from server while in download"

        elif isinstance(pkt, TftpPacketERR):
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received ERR from server: " + str(pkt)

        else:
            self.sendError(TftpErrors.IllegalTftpOp)
            raise TftpException, "Received unknown packet type from server: " + str(pkt)

        # By default, no state change.
        return self


###############################################################################
# Context classes
###############################################################################

class TftpContext(object):
    """The base class of the contexts."""

    def __init__(self, host, port, timeout):
        """Constructor for the base context, setting shared instance
        variables."""
        self.file_to_transfer = None
        self.fileobj = None
        self.options = None
        self.packethook = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.timeout = timeout
        self.state = None
        self.next_block = 0
        self.factory = TftpPacketFactory()
        # Note, setting the host will also set self.address, as it's a property.
        self.host = host
        self.port = port
        # The port associated with the TID
        self.tidport = None
        # Metrics
        self.metrics = TftpMetrics()
        # Fluag when the transfer is pending completion.
        self.pending_complete = False
        # Time when this context last received any traffic.
        # FIXME: does this belong in metrics?
        self.last_update = 0
        # The last packet we sent, if applicable, to make resending easy.
        self.last_pkt = None
        # Count the number of retry attempts.
        self.retry_count = 0

    def getBlocksize(self):
        """Fetch the current blocksize for this session."""
        return int(self.options.get('blksize', 512))

    def __del__(self):
        """Simple destructor to try to call housekeeping in the end method if
        not called explicitely. Leaking file descriptors is not a good
        thing."""
        self.end()

    def checkTimeout(self, now):
        """Compare current time with last_update time, and raise an exception
        if we're over the timeout time."""
        log.debug("checking for timeout on session %s", self)
        if now - self.last_update > self.timeout:
            raise TftpTimeout, "Timeout waiting for traffic"

    def start(self):
        raise NotImplementedError, "Abstract method"

    def end(self):
        """Perform session cleanup, since the end method should always be
        called explicitely by the calling code, this works better than the
        destructor."""
        log.debug("in TftpContext.end")
        self.sock.close()
        if self.fileobj is not None and not self.fileobj.closed:
            log.debug("self.fileobj is open - closing")
            self.fileobj.close()

    def gethost(self):
        "Simple getter method for use in a property."
        return self.__host

    def sethost(self, host):
        """Setter method that also sets the address property as a result
        of the host that is set."""
        self.__host = host
        self.address = socket.gethostbyname(host)

    host = property(gethost, sethost)

    def setNextBlock(self, block):
        if block >= 2 ** 16:
            log.debug("Block number rollover to 0 again")
            block = 0
        self.__eblock = block

    def getNextBlock(self):
        return self.__eblock

    next_block = property(getNextBlock, setNextBlock)

    def cycle(self):
        """Here we wait for a response from the server after sending it
        something, and dispatch appropriate action to that response."""
        try:
            (buffer, (raddress, rport)) = self.sock.recvfrom(MAX_BLKSIZE)
        except socket.timeout:
            log.warn("Timeout waiting for traffic, retrying...")
            raise TftpTimeout, "Timed-out waiting for traffic"

        # Ok, we've received a packet. Log it.
        log.debug("Received %d bytes from %s:%s",
                  len(buffer), raddress, rport)
        # And update our last updated time.
        self.last_update = time.time()

        # Decode it.
        recvpkt = self.factory.parse(buffer)

        # Check for known "connection".
        if raddress != self.address:
            log.warn("Received traffic from %s, expected host %s. Discarding"
                     % (raddress, self.host))

        if self.tidport and self.tidport != rport:
            log.warn("Received traffic from %s:%s but we're "
                     "connected to %s:%s. Discarding."
                     % (raddress, rport,
                        self.host, self.tidport))

        # If there is a packethook defined, call it. We unconditionally
        # pass all packets, it's up to the client to screen out different
        # kinds of packets. This way, the client is privy to things like
        # negotiated options.
        if self.packethook:
            self.packethook(recvpkt)

        # And handle it, possibly changing state.
        self.state = self.state.handle(recvpkt, raddress, rport)
        # If we didn't throw any exceptions here, reset the retry_count to
        # zero.
        self.retry_count = 0


class TftpContextServer(TftpContext):
    """The context for the server."""

    def __init__(self, host, port, timeout, root, dyn_file_func=None):
        TftpContext.__init__(self,
                             host,
                             port,
                             timeout,
                             )
        # At this point we have no idea if this is a download or an upload. We
        # need to let the start state determine that.
        self.state = TftpStateServerStart(self)

        self.root = root
        self.dyn_file_func = dyn_file_func

    def __str__(self):
        return "%s:%s %s" % (self.host, self.port, self.state)

    def start(self, buffer):
        """Start the state cycle. Note that the server context receives an
        initial packet in its start method. Also note that the server does not
        loop on cycle(), as it expects the TftpServer object to manage
        that."""
        log.debug("In TftpContextServer.start")
        self.metrics.start_time = time.time()
        log.debug("Set metrics.start_time to %s", self.metrics.start_time)
        # And update our last updated time.
        self.last_update = time.time()

        pkt = self.factory.parse(buffer)
        log.debug("TftpContextServer.start() - factory returned a %s", pkt)

        # Call handle once with the initial packet. This should put us into
        # the download or the upload state.
        self.state = self.state.handle(pkt,
                                       self.host,
                                       self.port)

    def end(self):
        """Finish up the context."""
        TftpContext.end(self)
        self.metrics.end_time = time.time()
        log.debug("Set metrics.end_time to %s", self.metrics.end_time)
        self.metrics.compute()


class TftpContextClientUpload(TftpContext):
    """The upload context for the client during an upload.
    Note: If input is a hyphen, then we will use stdin."""

    def __init__(self,
                 host,
                 port,
                 filename,
                 input,
                 options,
                 packethook,
                 timeout):
        TftpContext.__init__(self,
                             host,
                             port,
                             timeout)
        self.file_to_transfer = filename
        self.options = options
        self.packethook = packethook
        # If the input object has a read() function,
        # assume it is file-like.
        if hasattr(input, 'read'):
            self.fileobj = input
        elif input == '-':
            self.fileobj = sys.stdin
        else:
            self.fileobj = open(input, "rb")

        log.debug("TftpContextClientUpload.__init__()")
        log.debug("file_to_transfer = %s, options = %s",
                  self.file_to_transfer, self.options)

    def __str__(self):
        return "%s:%s %s" % (self.host, self.port, self.state)

    def start(self):
        log.info("Sending tftp upload request to %s" % self.host)
        log.info("    filename -> %s" % self.file_to_transfer)
        log.info("    options -> %s" % self.options)

        self.metrics.start_time = time.time()
        log.debug("Set metrics.start_time to %s", self.metrics.start_time)

        # FIXME: put this in a sendWRQ method?
        pkt = TftpPacketWRQ()
        pkt.filename = self.file_to_transfer
        pkt.mode = "octet"  # FIXME - shouldn't hardcode this
        pkt.options = self.options
        self.sock.sendto(pkt.encode().buffer, (self.host, self.port))
        self.next_block = 1
        self.last_pkt = pkt
        # FIXME: should we centralize sendto operations so we can refactor all
        # saving of the packet to the last_pkt field?

        self.state = TftpStateSentWRQ(self)

        while self.state:
            try:
                log.debug("State is %s", self.state)
                self.cycle()
            except TftpTimeout, err:
                log.error(str(err))
                self.retry_count += 1
                if self.retry_count >= TIMEOUT_RETRIES:
                    log.debug("hit max retries, giving up")
                    raise
                else:
                    log.warn("resending last packet")
                    self.state.resendLast()

    def end(self):
        """Finish up the context."""
        TftpContext.end(self)
        self.metrics.end_time = time.time()
        log.debug("Set metrics.end_time to %s", self.metrics.end_time)
        self.metrics.compute()


class TftpContextClientDownload(TftpContext):
    """The download context for the client during a download.
    Note: If output is a hyphen, then the output will be sent to stdout."""

    def __init__(self,
                 host,
                 port,
                 filename,
                 output,
                 options,
                 packethook,
                 timeout):
        TftpContext.__init__(self,
                             host,
                             port,
                             timeout)
        # FIXME: should we refactor setting of these params?
        self.file_to_transfer = filename
        self.options = options
        self.packethook = packethook
        # If the output object has a write() function,
        # assume it is file-like.
        if hasattr(output, 'write'):
            self.fileobj = output
        # If the output filename is -, then use stdout
        elif output == '-':
            self.fileobj = sys.stdout
        else:
            self.fileobj = open(output, "wb")

        log.debug("TftpContextClientDownload.__init__()")
        log.debug("file_to_transfer = %s, options = %s",
                  self.file_to_transfer, self.options)

    def __str__(self):
        return "%s:%s %s" % (self.host, self.port, self.state)

    def start(self):
        """Initiate the download."""
        log.info("Sending tftp download request to %s" % self.host)
        log.info("    filename -> %s" % self.file_to_transfer)
        log.info("    options -> %s" % self.options)

        self.metrics.start_time = time.time()
        log.debug("Set metrics.start_time to %s", self.metrics.start_time)

        # FIXME: put this in a sendRRQ method?
        pkt = TftpPacketRRQ()
        pkt.filename = self.file_to_transfer
        pkt.mode = "octet"  # FIXME - shouldn't hardcode this
        pkt.options = self.options
        self.sock.sendto(pkt.encode().buffer, (self.host, self.port))
        self.next_block = 1
        self.last_pkt = pkt

        self.state = TftpStateSentRRQ(self)

        while self.state:
            try:
                log.debug("State is %s", self.state)
                self.cycle()
            except TftpTimeout, err:
                log.error(str(err))
                self.retry_count += 1
                if self.retry_count >= TIMEOUT_RETRIES:
                    log.debug("hit max retries, giving up")
                    raise
                else:
                    log.warn("resending last packet")
                    self.state.resendLast()

    def end(self):
        """Finish up the context."""
        TftpContext.end(self)
        self.metrics.end_time = time.time()
        log.debug("Set metrics.end_time to %s", self.metrics.end_time)
        self.metrics.compute()


class TftpSession(object):
    """This class is the base class for the tftp client and server. Any shared
    code should be in this class."""
    # FIXME: do we need this anymore?
    pass


class TftpPacketWithOptions(object):
    """This class exists to permit some TftpPacket subclasses to share code
    regarding options handling. It does not inherit from TftpPacket, as the
    goal is just to share code here, and not cause diamond inheritance."""

    def __init__(self):
        self.options = {}

    def setoptions(self, options):
        log.debug("in TftpPacketWithOptions.setoptions")
        log.debug("options: %s", str(options))
        myoptions = {}
        for key in options:
            newkey = str(key)
            myoptions[newkey] = str(options[key])
            log.debug("populated myoptions with %s = %s",
                      newkey, myoptions[newkey])

        log.debug("setting options hash to: %s", str(myoptions))
        self._options = myoptions

    def getoptions(self):
        log.debug("in TftpPacketWithOptions.getoptions")
        return self._options

    # Set up getter and setter on options to ensure that they are the proper
    # type. They should always be strings, but we don't need to force the
    # client to necessarily enter strings if we can avoid it.
    options = property(getoptions, setoptions)

    def decode_options(self, buffer):
        """This method decodes the section of the buffer that contains an
        unknown number of options. It returns a dictionary of option names and
        values."""
        format = "!"
        options = {}

        log.debug("decode_options: buffer is: %s", repr(buffer))
        log.debug("size of buffer is %d bytes", len(buffer))
        if len(buffer) == 0:
            log.debug("size of buffer is zero, returning empty hash")
            return {}

        # Count the nulls in the buffer. Each one terminates a string.
        log.debug("about to iterate options buffer counting nulls")
        length = 0
        for c in buffer:
            if ord(c) == 0:
                log.debug("found a null at length %d", length)
                if length > 0:
                    format += "%dsx" % length
                    length = -1
                else:
                    raise TftpException, "Invalid options in buffer"
            length += 1

        log.debug("about to unpack, format is: %s", format)
        mystruct = struct.unpack(format, buffer)

        tftpassert(len(mystruct) % 2 == 0,
                   "packet with odd number of option/value pairs")

        for i in range(0, len(mystruct), 2):
            log.debug("setting option %s to %s", mystruct[i], mystruct[i + 1])
            options[mystruct[i]] = mystruct[i + 1]

        return options


class TftpPacket(object):
    """This class is the parent class of all tftp packet classes. It is an
    abstract class, providing an interface, and should not be instantiated
    directly."""

    def __init__(self):
        self.opcode = 0
        self.buffer = None

    def encode(self):
        """The encode method of a TftpPacket takes keyword arguments specific
        to the type of packet, and packs an appropriate buffer in network-byte
        order suitable for sending over the wire.

        This is an abstract method."""
        raise NotImplementedError, "Abstract method"

    def decode(self):
        """The decode method of a TftpPacket takes a buffer off of the wire in
        network-byte order, and decodes it, populating internal properties as
        appropriate. This can only be done once the first 2-byte opcode has
        already been decoded, but the data section does include the entire
        datagram.

        This is an abstract method."""
        raise NotImplementedError, "Abstract method"


class TftpPacketInitial(TftpPacket, TftpPacketWithOptions):
    """This class is a common parent class for the RRQ and WRQ packets, as
    they share quite a bit of code."""

    def __init__(self):
        TftpPacket.__init__(self)
        TftpPacketWithOptions.__init__(self)
        self.filename = None
        self.mode = None

    def encode(self):
        """Encode the packet's buffer from the instance variables."""
        tftpassert(self.filename, "filename required in initial packet")
        tftpassert(self.mode, "mode required in initial packet")

        ptype = None
        if self.opcode == 1:
            ptype = "RRQ"
        else:
            ptype = "WRQ"
        log.debug("Encoding %s packet, filename = %s, mode = %s",
                  ptype, self.filename, self.mode)
        for key in self.options:
            log.debug("    Option %s = %s", key, self.options[key])

        format = "!H"
        format += "%dsx" % len(self.filename)
        if self.mode == "octet":
            format += "5sx"
        else:
            raise AssertionError, "Unsupported mode: %s" % self.mode
        # Add options.
        options_list = []
        if self.options.keys() > 0:
            log.debug("there are options to encode")
            for key in self.options:
                # Populate the option name
                format += "%dsx" % len(key)
                options_list.append(key)
                # Populate the option value
                format += "%dsx" % len(str(self.options[key]))
                options_list.append(str(self.options[key]))

        log.debug("format is %s", format)
        log.debug("options_list is %s", options_list)
        log.debug("size of struct is %d", struct.calcsize(format))

        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.filename,
                                  self.mode,
                                  *options_list)

        log.debug("buffer is %s", repr(self.buffer))
        return self

    def decode(self):
        tftpassert(self.buffer, "Can't decode, buffer is empty")

        # FIXME - this shares a lot of code with decode_options
        nulls = 0
        format = ""
        nulls = length = tlength = 0
        log.debug("in decode: about to iterate buffer counting nulls")
        subbuf = self.buffer[2:]
        for c in subbuf:
            if ord(c) == 0:
                nulls += 1
                log.debug("found a null at length %d, now have %d", length, nulls)
                format += "%dsx" % length
                length = -1
                # At 2 nulls, we want to mark that position for decoding.
                if nulls == 2:
                    break
            length += 1
            tlength += 1

        log.debug("hopefully found end of mode at length %d", tlength)
        # length should now be the end of the mode.
        tftpassert(nulls == 2, "malformed packet")
        shortbuf = subbuf[:tlength + 1]
        log.debug("about to unpack buffer with format: %s", format)
        log.debug("unpacking buffer: %s", repr(shortbuf))
        mystruct = struct.unpack(format, shortbuf)

        tftpassert(len(mystruct) == 2, "malformed packet")
        self.filename = mystruct[0]
        self.mode = mystruct[1].lower()  # force lc - bug 17
        log.debug("set filename to %s", self.filename)
        log.debug("set mode to %s", self.mode)

        self.options = self.decode_options(subbuf[tlength + 1:])
        return self


class TftpPacketRRQ(TftpPacketInitial):
    """
::

            2 bytes    string   1 byte     string   1 byte
            -----------------------------------------------
    RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
    WRQ     -----------------------------------------------
    """

    def __init__(self):
        TftpPacketInitial.__init__(self)
        self.opcode = 1

    def __str__(self):
        s = 'RRQ packet: filename = %s' % self.filename
        s += ' mode = %s' % self.mode
        if self.options:
            s += '\n    options = %s' % self.options
        return s


class TftpPacketWRQ(TftpPacketInitial):
    """
::

            2 bytes    string   1 byte     string   1 byte
            -----------------------------------------------
    RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
    WRQ     -----------------------------------------------
    """

    def __init__(self):
        TftpPacketInitial.__init__(self)
        self.opcode = 2

    def __str__(self):
        s = 'WRQ packet: filename = %s' % self.filename
        s += ' mode = %s' % self.mode
        if self.options:
            s += '\n    options = %s' % self.options
        return s


class TftpPacketDAT(TftpPacket):
    """
::

            2 bytes    2 bytes       n bytes
            ---------------------------------
    DATA  | 03    |   Block #  |    Data    |
            ---------------------------------
    """

    def __init__(self):
        TftpPacket.__init__(self)
        self.opcode = 3
        self.blocknumber = 0
        self.data = None

    def __str__(self):
        s = 'DAT packet: block %s' % self.blocknumber
        if self.data:
            s += '\n    data: %d bytes' % len(self.data)
        return s

    def encode(self):
        """Encode the DAT packet. This method populates self.buffer, and
        returns self for easy method chaining."""
        if len(self.data) == 0:
            log.debug("Encoding an empty DAT packet")
        format = "!HH%ds" % len(self.data)
        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.blocknumber,
                                  self.data)
        return self

    def decode(self):
        """Decode self.buffer into instance variables. It returns self for
        easy method chaining."""
        # We know the first 2 bytes are the opcode. The second two are the
        # block number.
        (self.blocknumber,) = struct.unpack("!H", self.buffer[2:4])
        log.debug("decoding DAT packet, block number %d", self.blocknumber)
        log.debug("should be %d bytes in the packet total", len(self.buffer))
        # Everything else is data.
        self.data = self.buffer[4:]
        log.debug("found %d bytes of data", len(self.data))
        return self


class TftpPacketACK(TftpPacket):
    """
::

            2 bytes    2 bytes
            -------------------
    ACK   | 04    |   Block #  |
            --------------------
    """

    def __init__(self):
        TftpPacket.__init__(self)
        self.opcode = 4
        self.blocknumber = 0

    def __str__(self):
        return 'ACK packet: block %d' % self.blocknumber

    def encode(self):
        log.debug("encoding ACK: opcode = %d, block = %d",
                  self.opcode, self.blocknumber)
        self.buffer = struct.pack("!HH", self.opcode, self.blocknumber)
        return self

    def decode(self):
        self.opcode, self.blocknumber = struct.unpack("!HH", self.buffer)
        log.debug("decoded ACK packet: opcode = %d, block = %d",
                  self.opcode, self.blocknumber)
        return self


class TftpPacketERR(TftpPacket):
    """
::

            2 bytes  2 bytes        string    1 byte
            ----------------------------------------
    ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
            ----------------------------------------

    Error Codes

    Value     Meaning

    0         Not defined, see error message (if any).
    1         File not found.
    2         Access violation.
    3         Disk full or allocation exceeded.
    4         Illegal TFTP operation.
    5         Unknown transfer ID.
    6         File already exists.
    7         No such user.
    8         Failed to negotiate options
    """

    def __init__(self):
        TftpPacket.__init__(self)
        self.opcode = 5
        self.errorcode = 0
        # FIXME: We don't encode the errmsg...
        self.errmsg = None
        # FIXME - integrate in TftpErrors references?
        self.errmsgs = {
            1: "File not found",
            2: "Access violation",
            3: "Disk full or allocation exceeded",
            4: "Illegal TFTP operation",
            5: "Unknown transfer ID",
            6: "File already exists",
            7: "No such user",
            8: "Failed to negotiate options"
        }

    def __str__(self):
        s = 'ERR packet: errorcode = %d' % self.errorcode
        s += '\n    msg = %s' % self.errmsgs.get(self.errorcode, '')
        return s

    def encode(self):
        """Encode the DAT packet based on instance variables, populating
        self.buffer, returning self."""
        format = "!HH%dsx" % len(self.errmsgs[self.errorcode])
        log.debug("encoding ERR packet with format %s", format)
        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.errorcode,
                                  self.errmsgs[self.errorcode])
        return self

    def decode(self):
        "Decode self.buffer, populating instance variables and return self."
        buflen = len(self.buffer)
        tftpassert(buflen >= 4, "malformed ERR packet, too short")
        log.debug("Decoding ERR packet, length %s bytes", buflen)
        if buflen == 4:
            log.debug("Allowing this affront to the RFC of a 4-byte packet")
            format = "!HH"
            log.debug("Decoding ERR packet with format: %s", format)
            self.opcode, self.errorcode = struct.unpack(format,
                                                        self.buffer)
        else:
            log.debug("Good ERR packet > 4 bytes")
            format = "!HH%dsx" % (len(self.buffer) - 5)
            log.debug("Decoding ERR packet with format: %s", format)
            self.opcode, self.errorcode, self.errmsg = struct.unpack(format,
                                                                     self.buffer)
        log.error("ERR packet - errorcode: %d, message: %s"
                  % (self.errorcode, self.errmsg))
        return self


class TftpPacketOACK(TftpPacket, TftpPacketWithOptions):
    """
::

    +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    |  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
    +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    """

    def __init__(self):
        TftpPacket.__init__(self)
        TftpPacketWithOptions.__init__(self)
        self.opcode = 6

    def __str__(self):
        return 'OACK packet:\n    options = %s' % self.options

    def encode(self):
        format = "!H"  # opcode
        options_list = []
        log.debug("in TftpPacketOACK.encode")
        for key in self.options:
            log.debug("looping on option key %s", key)
            log.debug("value is %s", self.options[key])
            format += "%dsx" % len(key)
            format += "%dsx" % len(self.options[key])
            options_list.append(key)
            options_list.append(self.options[key])
        self.buffer = struct.pack(format, self.opcode, *options_list)
        return self

    def decode(self):
        self.options = self.decode_options(self.buffer[2:])
        return self

    def match_options(self, options):
        """This method takes a set of options, and tries to match them with
        its own. It can accept some changes in those options from the server as
        part of a negotiation. Changed or unchanged, it will return a dict of
        the options so that the session can update itself to the negotiated
        options."""
        for name in self.options:
            if options.has_key(name):
                if name == 'blksize':
                    # We can accept anything between the min and max values.
                    size = self.options[name]
                    if size >= MIN_BLKSIZE and size <= MAX_BLKSIZE:
                        log.debug("negotiated blksize of %d bytes", size)
                        options['blksize'] = size
                else:
                    raise TftpException, "Unsupported option: %s" % name
        return True


class TftpServer(TftpSession):
    """This class implements a tftp server object. Run the listen() method to
    listen for client requests.  It takes two optional arguments. tftproot is
    the path to the tftproot directory to serve files from and/or write them
    to. dyn_file_func is a callable that must return a file-like object to
    read from during downloads. This permits the serving of dynamic
    content."""

    def __init__(self, tftproot='/tftpboot', dyn_file_func=None):
        self.listenip = None
        self.listenport = None
        self.sock = None
        # FIXME: What about multiple roots?
        self.root = os.path.abspath(tftproot)
        self.dyn_file_func = dyn_file_func
        # A dict of sessions, where each session is keyed by a string like
        # ip:tid for the remote end.
        self.sessions = {}
        # A threading event to help threads synchronize with the server
        # is_running state.
        self.is_running = threading.Event()

        self.shutdown_gracefully = False
        self.shutdown_immediately = False

        if self.dyn_file_func:
            if not callable(self.dyn_file_func):
                raise TftpException, "A dyn_file_func supplied, but it is not callable."
        elif os.path.exists(self.root):
            log.debug("tftproot %s does exist", self.root)
            if not os.path.isdir(self.root):
                raise TftpException, "The tftproot must be a directory."
            else:
                log.debug("tftproot %s is a directory", self.root)
                if os.access(self.root, os.R_OK):
                    log.debug("tftproot %s is readable", self.root)
                else:
                    raise TftpException, "The tftproot must be readable"
                if os.access(self.root, os.W_OK):
                    log.debug("tftproot %s is writable", self.root)
                else:
                    log.warning("The tftproot %s is not writable" % self.root)
        else:
            raise TftpException, "The tftproot does not exist."

    def listen(self,
               listenip="",
               listenport=DEF_TFTP_PORT,
               timeout=SOCK_TIMEOUT):
        """Start a server listening on the supplied interface and port. This
        defaults to INADDR_ANY (all interfaces) and UDP port 69. You can also
        supply a different socket timeout value, if desired."""
        tftp_factory = TftpPacketFactory()

        # Don't use new 2.5 ternary operator yet
        # listenip = listenip if listenip else '0.0.0.0'
        if not listenip: listenip = '0.0.0.0'
        log.info("Server requested on ip %s, port %s"
                 % (listenip, listenport))
        try:
            # FIXME - sockets should be non-blocking
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((listenip, listenport))
            _, self.listenport = self.sock.getsockname()
        except socket.error, err:
            # Reraise it for now.
            raise

        self.is_running.set()

        log.info("Starting receive loop...")
        while True:
            log.debug("shutdown_immediately is %s", self.shutdown_immediately)
            log.debug("shutdown_gracefully is %s", self.shutdown_gracefully)
            if self.shutdown_immediately:
                log.warn("Shutting down now. Session count: %d" % len(self.sessions))
                self.sock.close()
                for key in self.sessions:
                    self.sessions[key].end()
                self.sessions = []
                break

            elif self.shutdown_gracefully:
                if not self.sessions:
                    log.warn("In graceful shutdown mode and all sessions complete.")
                    self.sock.close()
                    break

            # Build the inputlist array of sockets to select() on.
            inputlist = []
            inputlist.append(self.sock)
            for key in self.sessions:
                inputlist.append(self.sessions[key].sock)

            # Block until some socket has input on it.
            log.debug("Performing select on this inputlist: %s", inputlist)
            readyinput, readyoutput, readyspecial = select.select(inputlist,
                                                                  [],
                                                                  [],
                                                                  SOCK_TIMEOUT)

            deletion_list = []

            # Handle the available data, if any. Maybe we timed-out.
            for readysock in readyinput:
                # Is the traffic on the main server socket? ie. new session?
                if readysock == self.sock:
                    log.debug("Data ready on our main socket")
                    buffer, (raddress, rport) = self.sock.recvfrom(MAX_BLKSIZE)

                    log.debug("Read %d bytes", len(buffer))

                    if self.shutdown_gracefully:
                        log.warn("Discarding data on main port, in graceful shutdown mode")
                        continue

                    # Forge a session key based on the client's IP and port,
                    # which should safely work through NAT.
                    key = "%s:%s" % (raddress, rport)

                    if not self.sessions.has_key(key):
                        log.debug("Creating new server context for "
                                  "session key = %s", key)
                        self.sessions[key] = TftpContextServer(raddress,
                                                               rport,
                                                               timeout,
                                                               self.root,
                                                               self.dyn_file_func)
                        try:
                            self.sessions[key].start(buffer)
                        except TftpException, err:
                            deletion_list.append(key)
                            log.error("Fatal exception thrown from "
                                      "session %s: %s" % (key, str(err)))
                    else:
                        log.warn("received traffic on main socket for "
                                 "existing session??")
                    log.info("Currently handling these sessions:")
                    for session_key, session in self.sessions.items():
                        log.info("    %s" % session)

                else:
                    # Must find the owner of this traffic.
                    for key in self.sessions:
                        if readysock == self.sessions[key].sock:
                            log.info("Matched input to session key %s"
                                     % key)
                            try:
                                self.sessions[key].cycle()
                                if self.sessions[key].state == None:
                                    log.info("Successful transfer.")
                                    deletion_list.append(key)
                            except TftpException, err:
                                deletion_list.append(key)
                                log.error("Fatal exception thrown from "
                                          "session %s: %s"
                                          % (key, str(err)))
                            # Break out of for loop since we found the correct
                            # session.
                            break

                    else:
                        log.error("Can't find the owner for this packet. "
                                  "Discarding.")

            log.debug("Looping on all sessions to check for timeouts")
            now = time.time()
            for key in self.sessions:
                try:
                    self.sessions[key].checkTimeout(now)
                except TftpTimeout, err:
                    log.error(str(err))
                    self.sessions[key].retry_count += 1
                    if self.sessions[key].retry_count >= TIMEOUT_RETRIES:
                        log.debug("hit max retries on %s, giving up",
                                  self.sessions[key])
                        deletion_list.append(key)
                    else:
                        log.debug("resending on session %s", self.sessions[key])
                        self.sessions[key].state.resendLast()

            log.debug("Iterating deletion list.")
            for key in deletion_list:
                log.info('')
                log.info("Session %s complete" % key)
                if self.sessions.has_key(key):
                    log.debug("Gathering up metrics from session before deleting")
                    self.sessions[key].end()
                    metrics = self.sessions[key].metrics
                    if metrics.duration == 0:
                        log.info("Duration too short, rate undetermined")
                    else:
                        log.info("Transferred %d bytes in %.2f seconds"
                                 % (metrics.bytes, metrics.duration))
                        log.info("Average rate: %.2f kbps" % metrics.kbps)
                    log.info("%.2f bytes in resent data" % metrics.resent_bytes)
                    log.info("%d duplicate packets" % metrics.dupcount)
                    log.debug("Deleting session %s", key)
                    del self.sessions[key]
                    log.debug("Session list is now %s", self.sessions)
                else:
                    log.warn("Strange, session %s is not on the deletion list"
                             % key)

        self.is_running.clear()

        log.debug("server returning from while loop")
        self.shutdown_gracefully = self.shutdown_immediately = False

    def stop(self, now=False):
        """Stop the server gracefully. Do not take any new transfers,
        but complete the existing ones. If force is True, drop everything
        and stop. Note, immediately will not interrupt the select loop, it
        will happen when the server returns on ready data, or a timeout.
        ie. SOCK_TIMEOUT"""
        if now:
            self.shutdown_immediately = True
        else:
            self.shutdown_gracefully = True


if __name__ == '__main__':
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.DEBUG,
                        datefmt="%H:%M:%S")

    import threading

    s = TftpServer(tftproot=os.getcwd())
    t = threading.Thread(target=s.listen, args=('0.0.0.0', 25512))

    t.start()
