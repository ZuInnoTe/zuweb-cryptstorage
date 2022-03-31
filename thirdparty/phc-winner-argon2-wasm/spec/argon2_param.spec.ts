/**
 * This tests only the some of the verifications of parameters of the Argon2 library we developed in Typescript/Javascript, but not the Argon2 library itself.
 *
 * Note: We test mostly the parameters using argon2d_hash, but all other functions (argon2i, argon2id,argon2) are based on the same method to verify and thus tested as well
 */

import {
  Argon2,
  Argon2VerifyResult,
  Argon2Parameters,
  argon2_min_t_cost,
  argon2_min_m_cost,
  argon2_min_parallelism,
  argon2_min_size,
} from "../src/argon2";

describe("argon2d_hash with password less than minimal length", () => {
  it("throws exception", async () => {
    const password: string = "1";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    expect(function () {
      argon2.argon2d_hash(password, salt, keysize);
    }).toThrowError(
      "Password of length 1 does not correspond to minimal security settings."
    );
  });
});

describe("argon2d_hash with salt less than minimal length", () => {
  it("throws exception", async () => {
    const password: string = "passwordpassword";
    const salt: string = "1"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 32;
    const argon2: Argon2 = new Argon2();
    expect(function () {
      argon2.argon2d_hash(password, salt, keysize);
    }).toThrowError(
      "Salt of length 1 does not correspond to minimal security settings."
    );
  });
});

describe("argon2d_hash with less than minimal size", () => {
  it("throws exception", async () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const keysize: number = 1;
    const argon2: Argon2 = new Argon2();
    expect(function () {
      argon2.argon2d_hash(password, salt, keysize);
    }).toThrowError(
      `Size ${keysize} does not correspond to minimal security settings.`
    );
  });
});

describe("argon2d_hash with less than minimal t_cost", () => {
  it("throws exception", async () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const parameters: Argon2Parameters = {
      t_cost: 1,
      m_cost: argon2_min_m_cost,
      parallelism: argon2_min_parallelism,
    };
    const keysize: number = argon2_min_size;
    const argon2: Argon2 = new Argon2();
    expect(function () {
      argon2.argon2d_hash(password, salt, keysize, parameters);
    }).toThrowError(
      `Parameter t_cost does not fulfill minimal security settings.`
    );
  });
});

describe("argon2d_hash with less than minimal m_cost", () => {
  it("throws exception", async () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const parameters: Argon2Parameters = {
      t_cost: argon2_min_t_cost,
      m_cost: 1,
      parallelism: argon2_min_parallelism,
    };
    const keysize: number = argon2_min_size;
    const argon2: Argon2 = new Argon2();
    expect(function () {
      argon2.argon2d_hash(password, salt, keysize, parameters);
    }).toThrowError(
      `Parameter m_cost does not fulfill minimal security settings.`
    );
  });
});

describe("argon2d_hash with less than minimal parallelism", () => {
  it("throws exception", async () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const parameters: Argon2Parameters = {
      t_cost: argon2_min_t_cost,
      m_cost: argon2_min_m_cost,
      parallelism: 0,
    };
    const keysize: number = argon2_min_size;
    const argon2: Argon2 = new Argon2();
    expect(function () {
      argon2.argon2d_hash(password, salt, keysize, parameters);
    }).toThrowError(
      `Parameter parallelism does not fulfill minimal security settings.`
    );
  });
});

describe("argon2d_hash with more than minimal t_cost", () => {
  it("calculates hash correctly", async () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const parameters: Argon2Parameters = {
      t_cost: argon2_min_t_cost+1,
      m_cost: argon2_min_m_cost,
      parallelism: argon2_min_parallelism,
    };
    const keysize: number = argon2_min_size;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2d_hash(password, salt, keysize, parameters);
    const verify_result = argon2.argon2d_verify(actual_hash, password);
    expect(verify_result).toBe(Argon2VerifyResult.OK);
  });
});

describe("argon2d_hash with more than minimal m_cost", () => {
  it("calculates hash correctly", async () => {
    const password: string = "passwordpassword";
    const salt: string = "saltsaltsaltsalt"; // salt should be truely random - this here is just for testing purposes - never do this in a real application
    const parameters: Argon2Parameters = {
      t_cost: argon2_min_t_cost,
      m_cost: argon2_min_m_cost + 1,
      parallelism: argon2_min_parallelism,
    };
    const keysize: number = argon2_min_size;
    const argon2: Argon2 = new Argon2();
    const actual_hash = argon2.argon2d_hash(password, salt, keysize, parameters);
    const verify_result = argon2.argon2d_verify(actual_hash, password);
    expect(verify_result).toBe(Argon2VerifyResult.OK);
  });
});

