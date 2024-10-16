#include "stdio.h"
#include "stdlib.h"
#include "getopt.h"
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>
#include <fstream>
#include <vector>

/**
 * @brief Функция получения структуры RSA по её секретному ключу
 *
 * @param[in] key Секретный ключ
 *
 * @return Указатель на RSA
 */
RSA *createPrivateRSA(std::string key)
{
    RSA *rsa = NULL;
    const char *c_string = key.c_str();
    BIO *keybio = BIO_new_mem_buf((void *)c_string, -1);
    if (keybio == NULL)
    {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    return rsa;
}

/**
 * @brief Функция получения структуры RSA по её открытому ключу
 *
 * @param[in] key Открытый ключ
 *
 * @return Указатель на RSA
 */
RSA *createPublicRSA(std::string key)
{
    RSA *rsa = NULL;
    BIO *keybio;
    const char *c_string = key.c_str();
    keybio = BIO_new_mem_buf((void *)c_string, -1);
    if (keybio == NULL)
    {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    return rsa;
}

/**
 * @brief Функция выработки подписи на основе алгоритма RSA
 *
 * @param[in] rsa Указатель на структуру, описывающую схему RSA
 *
 * @param[in] Msg Указатель на подписываемое сообщение
 *
 * @param[in] MsgLen Размер подписываемого сообщения
 *
 * @param[out] EncMsg Указатель на место в памяти для записи указателя подписи
 *
 * @param[out] MsgLenEnc Указатель на место в памяти для записи размера подписи
 *
 * @return Успешность работы алгоритма выработки подписи
 */
bool RSASign(RSA *rsa,
             const unsigned char *Msg,
             size_t MsgLen,
             unsigned char **EncMsg,
             size_t *MsgLenEnc)
{
    EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY *priKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0)
    {
        return false;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
    {
        return false;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0)
    {
        return false;
    }
    *EncMsg = (unsigned char *)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0)
    {
        return false;
    }
    EVP_MD_CTX_free(m_RSASignCtx);
    return true;
}

/**
 * @brief Функция проверки подписи на основе алгоритма RSA
 *
 * @param[in] rsa Указатель на структуру, описывающую схему RSA
 *
 * @param[in] MsgHash Указатель на подпись
 *
 * @param[in] MsgHashLen Размер подписи
 *
 * @param[in] Msg Указатель на подписываемое сообщение
 *
 * @param[in] MsgLen Размер подписываемого сообщения
 *
 * @param[out] Authentic Результат отработанного алгоритма
 *
 * @return Успешность работы алгоритма проверки подписи
 */
bool RSAVerifySignature(RSA *rsa,
                        unsigned char *MsgHash,
                        size_t MsgHashLen,
                        const char *Msg,
                        size_t MsgLen,
                        bool *Authentic)
{
    *Authentic = false;
    EVP_PKEY *pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX *m_RSAVerifyCtx = EVP_MD_CTX_create();

    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
    {
        return false;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
    {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus == 1)
    {
        *Authentic = true;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    }
    else if (AuthStatus == 0)
    {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    }
    else
    {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return false;
    }
}

/**
 * @brief Функция, реализующая кодирование base64
 *
 * @param[in] buffer Указатель на исходный текст
 *
 * @param[in] length Размер исходного текста
 *
 * @param[out] base64Text Указатель на место в памяти для записи закодированного текста
 */
void Base64Encode(const unsigned char *buffer,
                  size_t length,
                  char **base64Text)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *base64Text = (*bufferPtr).data;
}

/**
 * @brief Функция вычисления закодированного в base64 текста
 *
 * @param[in] b64input Указатель на закодированный текст
 *
 * @return Размер закодированного текста
 */
size_t calcDecodeLength(const char *b64input)
{
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
        padding = 2;
    else if (b64input[len - 1] == '=')
        padding = 1;
    return (len * 3) / 4 - padding;
}

/**
 * @brief Функция, реализующая декодирование base64
 *
 * @param[in] b64message Указатель на закодированный текст
 *
 * @param[out] buffer Указатель на место в памяти для записи декодированного текста
 *
 * @param[out] length Размер декодированного текста
 */
void Base64Decode(const char *b64message, unsigned char **buffer, size_t *length)
{
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char *)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

/**
 * @brief Функция, реализующая выработку подписи с кодированием base64
 *
 * @param[in] privateKey Секретный ключ
 *
 * @param[in] plainText Исходный текст для выработки подписи
 *
 * @return Выработанная подпись
 */
char *signMessage(std::string privateKey, std::string plainText)
{
    RSA *privateRSA = createPrivateRSA(privateKey);
    unsigned char *encMessage;
    char *base64Text;
    size_t encMessageLength;
    RSASign(privateRSA, (unsigned char *)plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    return base64Text;
}

/**
 * @brief Функция, реализующая выработку подписи с кодированием base64
 *
 * @param[in] publicKey Открытый ключ
 *
 * @param[in] plainText Исходный текст, проверяемой подписи
 *
 * @param[in] signatureBase64 Закодированная в base64 подпись
 *
 * @return Результат проверки подписи
 */
bool verifySignature(std::string publicKey, std::string plainText, const char *signatureBase64)
{
    RSA *publicRSA = createPublicRSA(publicKey);
    unsigned char *encMessage;
    size_t encMessageLength;
    bool authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
    return result & authentic;
}

/**
 * @brief Функция чтения файла
 *
 * @param fileName Путь к файлу
 *
 * @return Содержимое файла
 */
std::string readFile(const std::string &fileName)
{
    std::ifstream ifs(fileName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

    std::ifstream::pos_type fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    std::vector<char> bytes(fileSize);
    ifs.read(bytes.data(), fileSize);

    return std::string(bytes.data(), fileSize);
}

/**
 * @brief Точка входа в программу
 *
 * @param argc Количество внешних аргументов программы
 *
 * @param argv Список указателей на внешние аргументы
 *
 * @return Статус завершения программы
 */
int main(int argc, char **argv)
{
    int opt;
    char *key = NULL;
    char sign = 0;
    char *verify = NULL;
    char *file = NULL;
    while ((opt = getopt(argc, argv, "k:sv:f:")) != -1)
    {
        switch (opt)
        {
        case 'k':
            key = optarg;
            break;
        case 's':
            sign = 1;
            break;
        case 'v':
            verify = optarg;
            break;
        case 'f':
            file = optarg;
            break;
        default:
            fprintf(stderr, "help: %s -k key [-s|-v signature] -f file\n", argv[0]);
            return 1;
        }
    }
    if ((!sign && verify == NULL) || key == NULL || file == NULL)
    {
        fprintf(stderr, "help: %s -k key [-s|-v signature] -f file\n", argv[0]);
        return 1;
    }
    if (sign && verify != NULL)
    {
        fprintf(stderr, "choose only one option [-s|-v]\n");
        return 1;
    }
    if (sign)
    {
        std::string key_data = readFile(key);
        std::string message = readFile(file);
        char *enc;
        try
        {
            enc = signMessage(key_data, message);
        }
        catch (const char *e)
        {
            std::cout << e << std::endl;
        }
        if (enc == NULL)
            return 1;
        char out_name[256] = "";
        sprintf(out_name, "%s.sig", file);
        FILE *out = fopen(out_name, "w");
        fprintf(out, "%s", enc);
        fclose(out);
        printf("Successfully signed\n");
    }
    if (verify != NULL)
    {
        std::string key_data = readFile(key);
        std::string message = readFile(file);
        std::string signature = readFile(verify);
        bool res = verifySignature(key_data, message, signature.c_str());
        if (res)
            printf("Verify: OK\n");
        else
            printf("Verify: Failed\n");
    }
    return 0;
}