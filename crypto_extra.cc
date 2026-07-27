/* Copyright (c) 2019,2024,2025,2026 MariaDB Corporation
   Copyright (c) 2026 lefred (Frédéric Descamps)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1335  USA */

#define MYSQL_SERVER

#include <my_global.h>
#include <sql_class.h>
#include <mysql/plugin_function.h>

#include <argon2.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {

static const uint MAX_ALGORITHM_NAME= 127;
static const uint MAX_RANDOM_LENGTH= 1024 * 1024;
static const uint MAX_DERIVED_KEY_LENGTH= 1024 * 1024;
static const ulonglong MAX_PBKDF2_ITERATIONS= 10000000;
static const uint ARGON2_SALT_LENGTH= 16;
static const uint ARGON2_DEFAULT_MEMORY= 64 * 1024;
static const uint ARGON2_DEFAULT_ITERATIONS= 3;
static const uint ARGON2_DEFAULT_PARALLELISM= 1;
static const uint ARGON2_DEFAULT_HASH_LENGTH= 32;
static const uint CRYPTO_ARGON2_MAX_MEMORY= 256 * 1024;
static const uint ARGON2_MAX_ITERATIONS= 10;
static const uint ARGON2_MAX_PARALLELISM= 16;
static const uint ARGON2_MIN_HASH_LENGTH= 16;
static const uint ARGON2_MAX_HASH_LENGTH= 64;

static bool get_string(Item *item, String *buffer, String **value)
{
  *value= item->val_str(buffer);
  return !*value || item->null_value;
}

static const EVP_MD *get_digest(const String &name)
{
  if (!name.length() || name.length() > MAX_ALGORITHM_NAME)
    return nullptr;

  char algorithm[MAX_ALGORITHM_NAME + 1];
  for (uint index= 0; index < name.length(); ++index)
  {
    char value= name.ptr()[index];
    algorithm[index]= value == '_' ? '-' : my_tolower(&my_charset_latin1,
                                                       value);
  }
  algorithm[name.length()]= '\0';

  if (!strcmp(algorithm, "sha") || !strcmp(algorithm, "sha-1"))
    return EVP_sha1();
  if (!strcmp(algorithm, "sha-224"))
    return EVP_sha224();
  if (!strcmp(algorithm, "sha-256"))
    return EVP_sha256();
  if (!strcmp(algorithm, "sha-384"))
    return EVP_sha384();
  if (!strcmp(algorithm, "sha-512"))
    return EVP_sha512();
  return EVP_get_digestbyname(algorithm);
}

static const EVP_CIPHER *get_cipher(const String &name, bool *padding)
{
  if (!name.length() || name.length() > MAX_ALGORITHM_NAME)
    return nullptr;

  char algorithm[MAX_ALGORITHM_NAME + 1];
  uint output= 0;
  uint suffix= name.length();
  for (uint index= 0; index < name.length(); ++index)
  {
    char value= name.ptr()[index];
    if (value == '/')
    {
      suffix= index;
      break;                            // pgcrypto's /pad:pkcs suffix
    }
    algorithm[output++]= value == '_' ? '-' :
        my_tolower(&my_charset_latin1, value);
  }
  algorithm[output]= '\0';

  *padding= true;
  if (suffix < name.length())
  {
    static const char pkcs_suffix[]= "/pad:pkcs";
    static const char none_suffix[]= "/pad:none";
    const size_t suffix_length= name.length() - suffix;
    if (suffix_length == sizeof(none_suffix) - 1 &&
        !my_strnncoll(&my_charset_latin1,
                      reinterpret_cast<const uchar *>(name.ptr() + suffix),
                      suffix_length,
                      reinterpret_cast<const uchar *>(none_suffix),
                      sizeof(none_suffix) - 1))
      *padding= false;
    else if (suffix_length != sizeof(pkcs_suffix) - 1 ||
             my_strnncoll(&my_charset_latin1,
                          reinterpret_cast<const uchar *>(name.ptr() + suffix),
                          suffix_length,
                          reinterpret_cast<const uchar *>(pkcs_suffix),
                          sizeof(pkcs_suffix) - 1))
      return nullptr;
  }

  const EVP_CIPHER *cipher;
  if (!strcmp(algorithm, "aes"))
    cipher= EVP_aes_128_cbc();
  else if (!strcmp(algorithm, "bf"))
    cipher= EVP_get_cipherbyname("bf-cbc");
  else
    cipher= EVP_get_cipherbyname(algorithm);

  // AEAD modes (GCM/CCM/...) need explicit tag handling that
  // Item_func_raw_cipher does not perform; reject them rather than
  // silently producing ciphertext with a discarded/missing tag.
  if (cipher && (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER))
    return nullptr;
  return cipher;
}

static bool set_binary_result(String *result, const uchar *data, size_t length)
{
  if (length > UINT_MAX || result->alloc(static_cast<uint>(length)))
    return true;
  if (length)
    memcpy(const_cast<char *>(result->ptr()), data, length);
  result->length(static_cast<uint>(length));
  result->set_charset(&my_charset_bin);
  return false;
}

template <typename Item_type, uint Minimum, uint Maximum= Minimum>
class Create_crypto_function : public Create_native_func
{
public:
  Item *create_native(THD *thd, const LEX_CSTRING *name,
                      List<Item> *items) override
  {
    uint count= items ? items->elements : 0;
    if (count < Minimum || count > Maximum)
    {
      my_error(ER_WRONG_PARAMCOUNT_TO_NATIVE_FCT, MYF(0), name->str);
      return nullptr;
    }
    return new (thd->mem_root) Item_type(thd, *items);
  }
};

class Item_crypto_string : public Item_str_func
{
public:
  using Item_str_func::Item_str_func;

  bool fix_length_and_dec(THD *) override
  {
    set_maybe_null();
    collation.set(&my_charset_bin, DERIVATION_COERCIBLE);
    return false;
  }
};

class Item_func_digest : public Item_crypto_string
{
  using Self= Item_func_digest;
public:
  using Item_crypto_string::Item_crypto_string;

  bool fix_length_and_dec(THD *thd) override
  {
    max_length= EVP_MAX_MD_SIZE;
    return Item_crypto_string::fix_length_and_dec(thd);
  }

  String *val_str(String *result) override
  {
    StringBuffer<256> data_buffer, name_buffer;
    String *data, *name;
    if (get_string(args[0], &data_buffer, &data) ||
        get_string(args[1], &name_buffer, &name))
      goto null;

    if (const EVP_MD *digest= get_digest(*name))
    {
      uchar output[EVP_MAX_MD_SIZE];
      uint length= 0;
      if (EVP_Digest(data->ptr(), data->length(), output, &length,
                     digest, nullptr) == 1 &&
          !set_binary_result(result, output, length))
      {
        null_value= false;
        return result;
      }
    }
null:
    null_value= true;
    return nullptr;
  }

  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "digest"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 2> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_hmac : public Item_crypto_string
{
  using Self= Item_func_hmac;
public:
  using Item_crypto_string::Item_crypto_string;

  bool fix_length_and_dec(THD *thd) override
  {
    max_length= EVP_MAX_MD_SIZE;
    return Item_crypto_string::fix_length_and_dec(thd);
  }

  String *val_str(String *result) override
  {
    StringBuffer<256> data_buffer, key_buffer, name_buffer;
    String *data, *key, *name;
    if (get_string(args[0], &data_buffer, &data) ||
        get_string(args[1], &key_buffer, &key) ||
        get_string(args[2], &name_buffer, &name) ||
        key->length() > INT_MAX)
      goto null;

    if (const EVP_MD *digest= get_digest(*name))
    {
      uchar output[EVP_MAX_MD_SIZE];
      uint length= 0;
      if (HMAC(digest, key->ptr(), static_cast<int>(key->length()),
               reinterpret_cast<const uchar *>(data->ptr()), data->length(),
               output, &length) &&
          !set_binary_result(result, output, length))
      {
        null_value= false;
        return result;
      }
    }
null:
    null_value= true;
    return nullptr;
  }

  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "hmac"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 3> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_pbkdf2_hmac : public Item_crypto_string
{
  using Self= Item_func_pbkdf2_hmac;
public:
  using Item_crypto_string::Item_crypto_string;

  bool fix_length_and_dec(THD *thd) override
  {
    max_length= MAX_DERIVED_KEY_LENGTH;
    return Item_crypto_string::fix_length_and_dec(thd);
  }

  String *val_str(String *result) override
  {
    StringBuffer<256> password_buffer, salt_buffer, name_buffer;
    String *password, *salt, *name;
    if (get_string(args[0], &password_buffer, &password) ||
        get_string(args[1], &salt_buffer, &salt))
      goto null;

    {
      longlong iterations_value= args[2]->val_int();
      if (args[2]->null_value || iterations_value <= 0 ||
          static_cast<ulonglong>(iterations_value) > MAX_PBKDF2_ITERATIONS)
        goto null;
      longlong length_value= args[3]->val_int();
      if (args[3]->null_value || length_value <= 0 ||
          static_cast<ulonglong>(length_value) > MAX_DERIVED_KEY_LENGTH ||
          password->length() > INT_MAX || salt->length() > INT_MAX)
        goto null;
      if (get_string(args[4], &name_buffer, &name))
        goto null;
      const EVP_MD *digest= get_digest(*name);
      if (!digest || result->alloc(static_cast<uint>(length_value)))
        goto null;
      if (PKCS5_PBKDF2_HMAC(
              password->ptr(), static_cast<int>(password->length()),
              reinterpret_cast<const uchar *>(salt->ptr()),
              static_cast<int>(salt->length()),
              static_cast<int>(iterations_value), digest,
              static_cast<int>(length_value),
              reinterpret_cast<uchar *>(const_cast<char *>(result->ptr()))) != 1)
        goto null;
      result->length(static_cast<uint>(length_value));
      result->set_charset(&my_charset_bin);
      null_value= false;
      return result;
    }
null:
    null_value= true;
    return nullptr;
  }

  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "pbkdf2_hmac"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 5> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_gen_random_bytes : public Item_crypto_string
{
  using Self= Item_func_gen_random_bytes;
public:
  using Item_crypto_string::Item_crypto_string;

  bool fix_length_and_dec(THD *thd) override
  {
    max_length= MAX_RANDOM_LENGTH;
    return Item_crypto_string::fix_length_and_dec(thd);
  }

  void update_used_tables() override
  {
    Item_crypto_string::update_used_tables();
    used_tables_cache|= RAND_TABLE_BIT;
  }

  String *val_str(String *result) override
  {
    longlong requested= args[0]->val_int();
    if (args[0]->null_value || requested < 1 ||
        requested > MAX_RANDOM_LENGTH ||
        result->alloc(static_cast<uint>(requested)) ||
        RAND_bytes(reinterpret_cast<uchar *>(
                       const_cast<char *>(result->ptr())),
                   static_cast<int>(requested)) != 1)
    {
      null_value= true;
      return nullptr;
    }
    result->length(static_cast<uint>(requested));
    result->set_charset(&my_charset_bin);
    null_value= false;
    return result;
  }

  bool check_vcol_func_processor(void *arg) override
  {
    return mark_unsupported_function(func_name(), "()", arg,
                                     VCOL_NON_DETERMINISTIC);
  }
  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "gen_random_bytes"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 1> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_random_bytes_hex : public Item_str_func
{
  using Self= Item_func_random_bytes_hex;
public:
  using Item_str_func::Item_str_func;

  bool fix_length_and_dec(THD *) override
  {
    max_length= 2 * MAX_RANDOM_LENGTH;
    set_maybe_null();
    collation.set(default_charset(), DERIVATION_COERCIBLE);
    return false;
  }

  void update_used_tables() override
  {
    Item_str_func::update_used_tables();
    used_tables_cache|= RAND_TABLE_BIT;
  }

  String *val_str(String *result) override
  {
    static const char digits[]= "0123456789ABCDEF";
    longlong requested= args[0]->val_int();
    if (args[0]->null_value || requested < 1 ||
        requested > MAX_RANDOM_LENGTH ||
        result->alloc(static_cast<uint>(requested) * 2))
      goto null;

    {
      uchar random[256];
      size_t remaining= static_cast<size_t>(requested);
      size_t output= 0;
      while (remaining)
      {
        int chunk= static_cast<int>(std::min(remaining, sizeof(random)));
        if (RAND_bytes(random, chunk) != 1)
          goto null;
        for (int index= 0; index < chunk; ++index)
        {
          const_cast<char *>(result->ptr())[output++]= digits[random[index] >> 4];
          const_cast<char *>(result->ptr())[output++]= digits[random[index] & 15];
        }
        remaining-= static_cast<size_t>(chunk);
      }
      result->length(static_cast<uint>(requested) * 2);
      result->set_charset(default_charset());
      null_value= false;
      return result;
    }
null:
    null_value= true;
    return nullptr;
  }

  bool check_vcol_func_processor(void *arg) override
  {
    return mark_unsupported_function(func_name(), "()", arg,
                                     VCOL_NON_DETERMINISTIC);
  }
  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "random_bytes_hex"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 1> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

static bool get_argon2_parameter(Item **args, uint index, uint count,
                                 uint default_value, uint minimum,
                                 uint maximum, uint *result)
{
  if (index >= count)
  {
    *result= default_value;
    return false;
  }
  longlong value= args[index]->val_int();
  if (args[index]->null_value || value < minimum ||
      static_cast<ulonglong>(value) > maximum)
    return true;
  *result= static_cast<uint>(value);
  return false;
}

class Item_func_argon2id_hash : public Item_str_func
{
  using Self= Item_func_argon2id_hash;
public:
  using Item_str_func::Item_str_func;

  bool fix_length_and_dec(THD *) override
  {
    // Worst case PHC string at the caps below (m=262144,t=10,p=16,
    // 64-byte hash) is ~150 bytes; 256 leaves headroom.
    max_length= 256;
    set_maybe_null();
    collation.set(default_charset(), DERIVATION_COERCIBLE);
    return false;
  }

  void update_used_tables() override
  {
    Item_str_func::update_used_tables();
    used_tables_cache|= RAND_TABLE_BIT;
  }

  String *val_str(String *result) override
  {
    StringBuffer<256> password_buffer;
    String *password;
    uint memory, iterations, parallelism, hash_length;
    if (get_string(args[0], &password_buffer, &password) ||
        get_argon2_parameter(args, 1, arg_count, ARGON2_DEFAULT_MEMORY,
                             8, CRYPTO_ARGON2_MAX_MEMORY, &memory) ||
        get_argon2_parameter(args, 2, arg_count, ARGON2_DEFAULT_ITERATIONS,
                             1, ARGON2_MAX_ITERATIONS, &iterations) ||
        get_argon2_parameter(args, 3, arg_count, ARGON2_DEFAULT_PARALLELISM,
                             1, ARGON2_MAX_PARALLELISM, &parallelism) ||
        get_argon2_parameter(args, 4, arg_count, ARGON2_DEFAULT_HASH_LENGTH,
                             ARGON2_MIN_HASH_LENGTH, ARGON2_MAX_HASH_LENGTH,
                             &hash_length) ||
        memory < 8 * parallelism)
      goto null;

    {
      uchar salt[ARGON2_SALT_LENGTH];
      if (RAND_bytes(salt, sizeof(salt)) != 1)
        goto null;
      size_t encoded_length= argon2_encodedlen(
          iterations, memory, parallelism, ARGON2_SALT_LENGTH, hash_length,
          Argon2_id);
      if (!encoded_length || encoded_length > UINT_MAX ||
          result->alloc(static_cast<uint>(encoded_length)))
        goto null;
      char *encoded= const_cast<char *>(result->ptr());
      if (argon2id_hash_encoded(
              iterations, memory, parallelism, password->ptr(),
              password->length(), salt, sizeof(salt), hash_length, encoded,
              encoded_length) != ARGON2_OK)
        goto null;
      result->length(static_cast<uint>(strlen(encoded)));
      result->set_charset(default_charset());
      null_value= false;
      return result;
    }
null:
    null_value= true;
    return nullptr;
  }

  bool check_vcol_func_processor(void *arg) override
  {
    return mark_unsupported_function(func_name(), "()", arg,
                                     VCOL_NON_DETERMINISTIC);
  }
  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "argon2id_hash"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 1, 5> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_argon2id_verify : public Item_bool_func
{
  using Self= Item_func_argon2id_verify;
public:
  using Item_bool_func::Item_bool_func;

  bool fix_length_and_dec(THD *thd) override
  {
    set_maybe_null();
    return Item_bool_func::fix_length_and_dec(thd);
  }

  bool val_bool() override
  {
    StringBuffer<256> password_buffer;
    StringBuffer<256> encoded_buffer;
    String *password, *encoded;
    if (get_string(args[0], &password_buffer, &password) ||
        get_string(args[1], &encoded_buffer, &encoded) ||
        encoded->length() > 1024 ||
        memchr(encoded->ptr(), '\0', encoded->length()))
      goto null;

    {
      char encoded_z[1025];
      memcpy(encoded_z, encoded->ptr(), encoded->length());
      encoded_z[encoded->length()]= '\0';
      uint version, memory, iterations, parallelism;
      if (sscanf(encoded_z, "$argon2id$v=%u$m=%u,t=%u,p=%u$",
                 &version, &memory, &iterations, &parallelism) != 4 ||
          version != ARGON2_VERSION_NUMBER ||
          memory < 8 * parallelism || memory > CRYPTO_ARGON2_MAX_MEMORY ||
          iterations < 1 || iterations > ARGON2_MAX_ITERATIONS ||
          parallelism < 1 || parallelism > ARGON2_MAX_PARALLELISM)
      {
        null_value= false;
        return false;
      }
      int status= argon2id_verify(encoded_z, password->ptr(),
                                  password->length());
      null_value= false;
      return status == ARGON2_OK;
    }
null:
    null_value= true;
    return false;
  }

  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "argon2id_verify"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 2> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_crypto_equals : public Item_bool_func
{
  using Self= Item_func_crypto_equals;
public:
  using Item_bool_func::Item_bool_func;

  bool fix_length_and_dec(THD *thd) override
  {
    set_maybe_null();
    return Item_bool_func::fix_length_and_dec(thd);
  }

  bool val_bool() override
  {
    StringBuffer<256> left_buffer, right_buffer;
    String *left, *right;
    if (get_string(args[0], &left_buffer, &left) ||
        get_string(args[1], &right_buffer, &right))
    {
      null_value= true;
      return 0;
    }
    null_value= false;
    if (left->length() != right->length())
      return 0;
    return CRYPTO_memcmp(left->ptr(), right->ptr(), left->length()) == 0;
  }

  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "crypto_equals"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 2> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_raw_cipher : public Item_crypto_string
{
  bool encrypt;
public:
  Item_func_raw_cipher(THD *thd, List<Item> &items, bool encrypt_arg)
    : Item_crypto_string(thd, items), encrypt(encrypt_arg) {}

  bool fix_length_and_dec(THD *thd) override
  {
    ulonglong length= args[0]->max_length;
    max_length= static_cast<uint32>(
        std::min<ulonglong>(UINT_MAX, length + EVP_MAX_BLOCK_LENGTH));
    return Item_crypto_string::fix_length_and_dec(thd);
  }

  String *val_str(String *result) override
  {
    StringBuffer<256> data_buffer, key_buffer, name_buffer, iv_buffer;
    String *data, *key, *name, *iv= nullptr;
    if (get_string(args[0], &data_buffer, &data) ||
        get_string(args[1], &key_buffer, &key) ||
        get_string(args[2], &name_buffer, &name) ||
        (arg_count == 4 && get_string(args[3], &iv_buffer, &iv)) ||
        data->length() > INT_MAX)
      goto null;

    {
      bool padding;
      const EVP_CIPHER *cipher= get_cipher(*name, &padding);
      if (!cipher || key->length() != static_cast<uint>(EVP_CIPHER_key_length(cipher)))
        goto null;
      const int iv_length= EVP_CIPHER_iv_length(cipher);
      if (iv && iv->length() != static_cast<uint>(iv_length))
        goto null;
      uchar zero_iv[EVP_MAX_IV_LENGTH]= {0};
      const uchar *iv_data= iv ?
          reinterpret_cast<const uchar *>(iv->ptr()) : zero_iv;

      EVP_CIPHER_CTX *context= EVP_CIPHER_CTX_new();
      if (!context)
        goto null;
      size_t capacity= data->length() + EVP_CIPHER_block_size(cipher);
      bool failed= capacity > UINT_MAX ||
                   result->alloc(static_cast<uint>(capacity));
      int first= 0, final= 0;
      if (!failed)
      {
        uchar *output= reinterpret_cast<uchar *>(
            const_cast<char *>(result->ptr()));
        if (encrypt)
        {
          failed= EVP_EncryptInit_ex(context, cipher, nullptr,
                      reinterpret_cast<const uchar *>(key->ptr()), iv_data) != 1 ||
                  EVP_CIPHER_CTX_set_padding(context, padding) != 1 ||
                  EVP_EncryptUpdate(context, output, &first,
                     reinterpret_cast<const uchar *>(data->ptr()),
                     static_cast<int>(data->length())) != 1 ||
                  EVP_EncryptFinal_ex(context, output + first, &final) != 1;
        }
        else
        {
          failed= EVP_DecryptInit_ex(context, cipher, nullptr,
                     reinterpret_cast<const uchar *>(key->ptr()), iv_data) != 1 ||
                  EVP_CIPHER_CTX_set_padding(context, padding) != 1 ||
                  EVP_DecryptUpdate(context, output, &first,
                     reinterpret_cast<const uchar *>(data->ptr()),
                     static_cast<int>(data->length())) != 1 ||
                  EVP_DecryptFinal_ex(context, output + first, &final) != 1;
        }
      }
      EVP_CIPHER_CTX_free(context);
      if (!failed)
      {
        result->length(static_cast<uint>(first + final));
        result->set_charset(&my_charset_bin);
        null_value= false;
        return result;
      }
    }
null:
    null_value= true;
    return nullptr;
  }
};

class Item_func_crypto_encrypt : public Item_func_raw_cipher
{
  using Self= Item_func_crypto_encrypt;
public:
  Item_func_crypto_encrypt(THD *thd, List<Item> &items)
    : Item_func_raw_cipher(thd, items, true) {}
  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "crypto_encrypt"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 3> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_crypto_decrypt : public Item_func_raw_cipher
{
  using Self= Item_func_crypto_decrypt;
public:
  Item_func_crypto_decrypt(THD *thd, List<Item> &items)
    : Item_func_raw_cipher(thd, items, false) {}
  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "crypto_decrypt"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 3> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_crypto_encrypt_iv : public Item_func_crypto_encrypt
{
  using Self= Item_func_crypto_encrypt_iv;
public:
  using Item_func_crypto_encrypt::Item_func_crypto_encrypt;
  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "crypto_encrypt_iv"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 4> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

class Item_func_crypto_decrypt_iv : public Item_func_crypto_decrypt
{
  using Self= Item_func_crypto_decrypt_iv;
public:
  using Item_func_crypto_decrypt::Item_func_crypto_decrypt;
  LEX_CSTRING func_name_cstring() const override
  { static LEX_CSTRING name= "crypto_decrypt_iv"_LEX_CSTRING; return name; }
  Item *shallow_copy(THD *thd) const override
  { return get_item_copy<Self>(thd, this); }
  static Plugin_function *plugin_descriptor()
  {
    static Create_crypto_function<Self, 4> creator;
    static Plugin_function descriptor(&creator);
    return &descriptor;
  }
};

} // namespace

#define CRYPTO_PLUGIN_ITEM(type, sql_name, description)                       \
  { MariaDB_FUNCTION_PLUGIN, type::plugin_descriptor(), sql_name, "lefred",  \
    description, PLUGIN_LICENSE_GPL, nullptr, nullptr, 0x0100, nullptr,      \
    nullptr, "1.0", MariaDB_PLUGIN_MATURITY_EXPERIMENTAL }

maria_declare_plugin(crypto_extra)
  CRYPTO_PLUGIN_ITEM(Item_func_digest, "digest", "Function DIGEST()"),
  CRYPTO_PLUGIN_ITEM(Item_func_hmac, "hmac", "Function HMAC()"),
  CRYPTO_PLUGIN_ITEM(Item_func_pbkdf2_hmac, "pbkdf2_hmac",
                     "Function PBKDF2_HMAC()"),
  CRYPTO_PLUGIN_ITEM(Item_func_gen_random_bytes, "gen_random_bytes",
                     "Function GEN_RANDOM_BYTES()"),
  CRYPTO_PLUGIN_ITEM(Item_func_random_bytes_hex, "random_bytes_hex",
                     "Function RANDOM_BYTES_HEX()"),
  CRYPTO_PLUGIN_ITEM(Item_func_argon2id_hash, "argon2id_hash",
                     "Function ARGON2ID_HASH()"),
  CRYPTO_PLUGIN_ITEM(Item_func_argon2id_verify, "argon2id_verify",
                     "Function ARGON2ID_VERIFY()"),
  CRYPTO_PLUGIN_ITEM(Item_func_crypto_equals, "crypto_equals",
                     "Function CRYPTO_EQUALS()"),
  CRYPTO_PLUGIN_ITEM(Item_func_crypto_encrypt, "crypto_encrypt",
                     "Function CRYPTO_ENCRYPT()"),
  CRYPTO_PLUGIN_ITEM(Item_func_crypto_decrypt, "crypto_decrypt",
                     "Function CRYPTO_DECRYPT()"),
  CRYPTO_PLUGIN_ITEM(Item_func_crypto_encrypt_iv, "crypto_encrypt_iv",
                     "Function CRYPTO_ENCRYPT_IV()"),
  CRYPTO_PLUGIN_ITEM(Item_func_crypto_decrypt_iv, "crypto_decrypt_iv",
                     "Function CRYPTO_DECRYPT_IV()")
maria_declare_plugin_end;
