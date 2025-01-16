#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KEY_SPEC_PROCESS_KEYRING	-2	/* - key ID for process-specifi*/
#define KEYCTL_UPDATE			2	/* update a key */
#define KEYCTL_REVOKE			3	/* revoke a key */
#define KEYCTL_UNLINK			9	/* unlink a key from a keyring */
#define KEYCTL_READ			11	/* read a key or keyring's cont*/

int key_alloc(char *description, char *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_update(int keyid, char *payload, size_t plen)
{
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int key_read(int keyid, char *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

int key_unlink(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}


