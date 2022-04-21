/**
 * These tests only the integration of the hash function of the Argon2 library with Typescript/Javascript, but not the Argon2 library itself.
 *
 */
import { Argon2, Argon2VerifyResult } from "../src/argon2";

describe("Argon2 Integration", () => {
  let argon2: Argon2;
  beforeEach(function () {
    argon2 = new Argon2();
  });
  afterEach(function () {
    argon2.close();
  });

  it("argon2d_hash generates and verifies the hash according to the correct password correctly", () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2d_hash(password, salt, keysize);
    const verify_result = argon2.argon2d_verify(actual_hash, password);
    expect(verify_result).toBe(Argon2VerifyResult.OK);
  });

  it("argon2d_hash generates and verifies the hash according to the wrong password correctly", () => {
    const password: string = "passwordpassword";
    const wrongpassword: string = "thisisthewrongpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2d_hash(password, salt, keysize);
    const verify_result = argon2.argon2d_verify(actual_hash, wrongpassword);
    expect(verify_result).toBe(Argon2VerifyResult.VERIFY_MISMATCH);
  });

  it("argon2i_hash generates and verifies the hash according to the correct password correctly", () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2i_hash(password, salt, keysize);
    const verify_result = argon2.argon2i_verify(actual_hash, password);
    expect(verify_result).toBe(Argon2VerifyResult.OK);
  });

  it("argon2i_hash generates and verifies the hash according to the wrong password correctly", () => {
    const password: string = "passwordpassword";
    const wrongpassword: string = "thisisthewrongpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2i_hash(password, salt, keysize);
    const verify_result = argon2.argon2i_verify(actual_hash, wrongpassword);
    expect(verify_result).toBe(Argon2VerifyResult.VERIFY_MISMATCH);
  });

  it("argon2id_hash generates and verifies the hash according to the correct password correctly", () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2id_hash(password, salt, keysize);
    const verify_result = argon2.argon2id_verify(actual_hash, password);
    expect(verify_result).toBe(Argon2VerifyResult.OK);
  });

  it("argon2id_hash generates and verifies the hash according to the wrong password correctly", () => {
    const password: string = "passwordpassword";
    const wrongpassword: string = "thisisthewrongpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2id_hash(password, salt, keysize);
    const verify_result = argon2.argon2id_verify(actual_hash, wrongpassword);
    expect(verify_result).toBe(Argon2VerifyResult.VERIFY_MISMATCH);
  });
});
