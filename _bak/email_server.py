from __future__ import print_function
from datetime import datetime
import asyncore
from smtpd import SMTPServer
import threading


class EmlServer(SMTPServer):
    no = 0

    def process_message(self, peer, mailfrom, rcpttos, data):
        print(data)

        # filename = '%s-%d.eml' % (datetime.now().strftime('%Y%m%d%H%M%S'),
        #         self.no)
        # f = open(filename, 'w')
        # f.write(data)
        # f.close()
        # print('%s saved.' % filename)
        self.no += 1


# This will probably not work on HSL?
def run():
    # start the smtp server on localhost:1025
    foo = EmlServer(('0.0.0.0', 1025), None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass


# class MyReceiver(object):
#     def start(self):
#         """Start the listening service"""
#         # here I create an instance of the SMTP server, derived from  asyncore.dispatcher
#         self.smtp = EmlServer(('0.0.0.0', 1025), None)
#
#         # and here I also start the asyncore loop, listening for SMTP connection, within a thread
#         # timeout parameter is important, otherwise code will block 30 seconds after the smtp channel has been closed
#         self.thread = threading.Thread(target=asyncore.loop,kwargs = {'timeout':1} )
#         self.thread.start()
#
#     def stop(self):
#         """Stop listening now to port 25"""
#         # close the SMTPserver to ensure no channels connect to asyncore
#         self.smtp.close()
#         # now it is save to wait for the thread to finish, i.e. for asyncore.loop() to exit
#         self.thread.join()

if __name__ == '__main__':
    run()
    # receiver = MyReceiver()
    #
    # try:
    #     print('START')
    #     receiver.start()
    # except KeyboardInterrupt:
    #     print('STOP')
    #     receiver.stop()
