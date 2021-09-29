#!/bin/bash

# Add local user
# Either use the LOCAL_USER_ID if passed in at runtime or
# fallback

USER_ID=${LOCAL_USER_ID:-0}
USERNAME=${LOCAL_USERNAME:-user}
CHOWNDIRS=${CHOWNDIRS}
VERBOSE=${VERBOSE}


case ${USER_ID} in
   "0")
        # Run as root
        exec "$@"
        ;;
   *)
        # Run as non-root
        if [[ ! $(getent passwd ${USERNAME} > /dev/null 2>&1) ]]; then
            if [ "${VERBOSE}" ]; then printf "creating user \"%s\" with UID \"%s\" ...\n" "${USERNAME}" "${USER_ID}"; fi
            adduser --system --shell /bin/bash --uid ${USER_ID} --disabled-password ${USERNAME} 1> /dev/null
        fi
        export HOME=/home/${USERNAME}

        # chown dirs
        if [ "${CHOWNDIRS}" ];
        then
            IFS=',' read -r -a array <<< "${CHOWNDIRS}"
            for element in "${array[@]}"
            do
                if [ "${VERBOSE}" ]; then printf "transfering directory ownership for %s to %s:%s ...\n" "${element}" "${USER_ID}" "${USER_ID}"; fi
                chown -R ${USER_ID}:${USER_ID} ${element};
            done
        fi

        # Exec statement
        exec gosu ${USERNAME} "$@"
        ;;
esac

