/**
 * This tests only the integration of the hash function of the Argon2 library with Typescript/Javascript, but not the Argon2 library itself.
 * 
 */
 import create_argon2_module from '../src/argon2wasm';
import {Argon2,Argon2VerifyResult} from '../src/argon2';

describe("argon2d_hash generates and verifies the hash according to the correct password", () => {
    it("correctly", async () => {
      const password: string="passwordpassword";
      const salt: string="saltsaltsaltsalt";
      const keysize: number=32;
      const argon2: Argon2 = new Argon2();
      const actual_hash=argon2.argon2d_hash(password,salt,keysize);
      const verify_result=argon2.argon2d_verify(actual_hash, password);
      expect(verify_result).toBe(Argon2VerifyResult.OK);
    });
  });
  
  describe("argon2d_hash generates and verifies the hash according to the wrong password", () => {
    it("correctly", async () => {
      const password: string="passwordpassword";
      const wrongpassword: string="thisisthewrongpassword";
      const salt: string="saltsaltsaltsalt";
      const keysize: number=32;
      const argon2: Argon2 = new Argon2();
      const actual_hash=argon2.argon2d_hash(password,salt,keysize);
      const verify_result=argon2.argon2d_verify(actual_hash, wrongpassword);
      expect(verify_result).toBe(Argon2VerifyResult.VERIFY_MISMATCH);
    });
  });

  describe("argon2i_hash generates and verifies the hash according to the correct password", () => {
    it("correctly", async () => {
      const password: string="passwordpassword";
      const salt: string="saltsaltsaltsalt";
      const keysize: number=32;
      const argon2: Argon2 = new Argon2();
      const actual_hash=argon2.argon2i_hash(password,salt,keysize);
      const verify_result=argon2.argon2i_verify(actual_hash, password);
      expect(verify_result).toBe(Argon2VerifyResult.OK);
    });
  });
  
  describe("argon2i_hash generates and verifies the hash according to the wrong password", () => {
    it("correctly", async () => {
      const password: string="passwordpassword";
      const wrongpassword: string="thisisthewrongpassword";
      const salt: string="saltsaltsaltsalt";
      const keysize: number=32;
      const argon2: Argon2 = new Argon2();
      const actual_hash=argon2.argon2i_hash(password,salt,keysize);
      const verify_result=argon2.argon2i_verify(actual_hash, wrongpassword);
      expect(verify_result).toBe(Argon2VerifyResult.VERIFY_MISMATCH);
    });
  });
  
  describe("argon2id_hash generates and verifies the hash according to the correct password", () => {
    it("correctly", async () => {
      const password: string="passwordpassword";
      const salt: string="saltsaltsaltsalt";
      const keysize: number=32;
      const argon2: Argon2 = new Argon2();
      const actual_hash=argon2.argon2id_hash(password,salt,keysize);
      const verify_result=argon2.argon2id_verify(actual_hash, password);
      expect(verify_result).toBe(Argon2VerifyResult.OK);
    });
  });
  
  describe("argon2id_hash generates and verifies the hash according to the wrong password", () => {
    it("correctly", async () => {
      const password: string="passwordpassword";
      const wrongpassword: string="thisisthewrongpassword";
      const salt: string="saltsaltsaltsalt";
      const keysize: number=32;
      const argon2: Argon2 = new Argon2();
      const actual_hash=argon2.argon2id_hash(password,salt,keysize);
      const verify_result=argon2.argon2id_verify(actual_hash, wrongpassword);
      expect(verify_result).toBe(Argon2VerifyResult.VERIFY_MISMATCH);
    });
  });
  