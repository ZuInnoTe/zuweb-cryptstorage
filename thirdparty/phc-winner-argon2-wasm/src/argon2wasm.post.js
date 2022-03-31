/**
 * Functions to facilitate integration with the methods from the Argon2 library
 *
 * Note: This is a raw integration with the Argon2 library and only very little validation of parameters are done. Especially, it is not checked if the parameters fullfil minimal security requirements.
 *
 */

const ARGON2_VERSION = {
  ARGON2_VERSION_10: 0x10,
  ARGON2_VERSION_13: 0x13,
  ARGON2_VERSION_NUMBER: 0x13,
};

/**
 * Calls the original argon2_hash function of the argon2 library compiled to WASM
 *
 * @param {*} pwd password to hash - note: please consider latest recommendations on the length
 * @param {*} salt salt to include - note: please ensure that it is truely random and consider latest recommendations on length
 * @param {*} modus modus of Argon2, e.g. d (0), i (1), id (2)
 * @param {*} t_cost time cost - note: please consider latest recommendations on minimal value
 * @param {*} m_cost memory cost - note: please consider latest recommendations on minimal value
 * @param {*} parallelism parallelism - note: please consider latest recommendations on minimal value
 * @param {*} size the size of the generated hash
 *
 * @returns Argon2 hash string of according to the parameters.
 */
function wasm_argon2_hash(pwd, salt, modus, t_cost, m_cost, parallelism, size) {
  // verify parameters
  if (!pwd || typeof pwd != "string")
    throw new TypeError(
      "Invalid parameters for argon2_hash: No password provided."
    );
  if (!salt || typeof salt != "string")
    throw new TypeError("Invalid parameters for argon2_hash: No salt provided");
  if (modus === undefined || typeof modus != "number")
    throw new TypeError(
      "Invalid parameters for argon2_hash: No valid modus provided"
    );
  if (parallelism === undefined || typeof parallelism != "number")
    throw new TypeError(
      "Invalid parameters for argon2_hash: No parallelism provided"
    );
  if (t_cost === undefined || typeof t_cost != "number")
    throw new TypeError(
      "Invalid parameters for argon2_hash: No time cost provided"
    );
  if (m_cost === undefined || typeof m_cost != "number")
    throw new TypeError(
      "Invalid parameters for argon2_hash: No memor cost provided"
    );
  // prepare parameters to be handed over to the wasm function
  const pwd_length = lengthBytesUTF8(pwd);
  const wasm_memory_password = _malloc(pwd_length + 1);
  stringToUTF8(pwd, wasm_memory_password, pwd_length + 1);

  const salt_length = lengthBytesUTF8(salt);
  const wasm_memory_salt = _malloc(salt_length + 1);
  stringToUTF8(salt, wasm_memory_salt, salt_length + 1);

  // prepare returned hash
  const wasm_memory_hash = null;
  const encoded_hash_length = (size + salt_length + 2) * 2 + 4 * 32;
  const wasm_memory_encoded_hash = _malloc(encoded_hash_length + 1);

  const returncode = _argon2_hash(
    t_cost,
    m_cost,
    parallelism,
    wasm_memory_password,
    pwd_length,
    wasm_memory_salt,
    salt_length,
    wasm_memory_hash,
    size,
    wasm_memory_encoded_hash,
    encoded_hash_length,
    modus,
    ARGON2_VERSION.ARGON2_VERSION_NUMBER
  );

  let hash_string;
  if (returncode == 0) {
    hash_string = UTF8ToString(wasm_memory_encoded_hash, encoded_hash_length);
  }
  _free(wasm_memory_password);
  _free(wasm_memory_salt);
  _free(wasm_memory_encoded_hash);

  if (returncode != 0) {
    throw new Error(
      `Could not calculate argon2 hash. Error code: ${returncode}.`
    );
  }

  return hash_string;
}
Module["wasm_argon2_hash"] = wasm_argon2_hash;

/**
 * Calls the original argon2_verify function of the original argon2 library compiled to WASM
 *
 * @param {*} hash to verify the password against
 * @param {*} pwd password to check if the hash corresponds to it
 * @param {*} modus modus of Argon2, e.g. d (0), i (1), id (2)
 *
 * @return 0 in case of match, otherwise error code
 */
function wasm_argon2_verify(hash, pwd, modus) {
  if (!hash || typeof hash != "string")
    throw new TypeError(
      "Invalid parameters for argon2_verify: No hash provided or hash too short."
    );
  if (!pwd || typeof pwd != "string")
    throw new TypeError(
      "Invalid parameters for argon2_verify: No password provided"
    );
  if (modus === undefined || typeof modus !== "number")
    throw new TypeError(
      "Invalid parameters for argon2_verifymake: No valid modus provided"
    );

  const hash_length = lengthBytesUTF8(hash);
  const wasm_memory_hash = _malloc(hash_length + 1);
  stringToUTF8(hash, wasm_memory_hash, hash_length + 1);

  const pwd_length = lengthBytesUTF8(pwd);
  const wasm_memory_pwd = _malloc(pwd_length + 1);
  stringToUTF8(pwd, wasm_memory_pwd, pwd_length + 1);

  const returncode = _argon2_verify(
    wasm_memory_hash,
    wasm_memory_pwd,
    pwd_length,
    modus
  );

  _free(wasm_memory_hash);
  _free(wasm_memory_pwd);

  return returncode;
}
Module["wasm_argon2_verify"] = wasm_argon2_verify;
