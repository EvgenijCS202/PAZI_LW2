#include "stdio.h"
#include "stdlib.h"
#include "getopt.h"

int genKeys()
{
    int res = 0;
    res |= system("openssl genpkey -out keys/privkey.pem -algorithm rsa");
    res |= system("openssl rsa -in keys/privkey.pem -outform PEM -pubout -out keys/pubkey.pem");
    printf("%d\n", res);
    return res;
}

int _sign(char *key, char *file)
{
    char cmd[2048] = "";
    sprintf(cmd, "openssl dgst -sha256 -sign %s -out sign.sha256 %s && openssl enc -base64 -in sign.sha256 -out %s.sig && del sign.sha256", key, file, file);
    return system(cmd);
}

int _verify(char *key, char *file)
{
    char cmd[2048] = "";
    sprintf(cmd, "openssl enc -base64 -d -in %s.sig -out sign.sha256 && openssl dgst -sha256 -verify %s -signature sign.sha256 %s && del sign.sha256", file, key, file);
    return system(cmd);
}

int main(int argc, char **argv)
{
    int opt;
    char gen_keys = 0;
    char *key = NULL;
    char sign = 0;
    char verify = 0;
    char *file = NULL;
    while ((opt = getopt(argc, argv, "gk:svf:")) != -1)
    {
        switch (opt)
        {
        case 'g':
            gen_keys = 1;
            break;
        case 'k':
            key = optarg;
            break;
        case 's':
            sign = 1;
            break;
        case 'v':
            verify = 1;
            break;
        case 'f':
            file = optarg;
            break;
        default:
            fprintf(2, "help: %s [-g|-k key] [-s|-v] -f file\n");
            return 1;
        }
    }
    if ((!sign && !verify) || (!gen_keys && key == NULL) || file == NULL)
    {
        fprintf(2, "help: %s [-g|-k key] [-s|-v] -f file\n");
        return 1;
    }
    if (sign && verify)
    {
        fprintf(2, "choose only one option [-s|-v]\n");
        return 1;
    }
    if (gen_keys && key != NULL)
    {
        fprintf(2, "choose only one option [-g|-k key]\n");
        return 1;
    }
    if (verify && key == NULL)
    {
        fprintf(2, "can't gen keys with verify\n");
        return 1;
    }
    if (gen_keys)
    {
        if (genKeys())
            return;
    }
    if (sign)
    {
        if (_sign(gen_keys ? "keys/privkey.pem" : key, file))
            return 1;
    }
    if (verify)
    {
        if (_verify(key, file))
            return 1;
    }
    return 0;
}