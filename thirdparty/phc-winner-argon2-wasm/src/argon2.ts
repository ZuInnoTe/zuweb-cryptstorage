/**
 * Typescript wrappper for the Argon2 WASM module.
 * 
 */
import create_argon2_module from './argon2wasm';
import {Argon2Module} from './argon2wasm';


/**  Minimal security parameters - recommendation is to go beyond them for high security
* based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
*/
const min_pwd_length = 12;
const min_salt_length = 16;
const min_t_cost = 3; // 3 s
const min_m_cost = 64*1024 ; // 2^N kibibytes, e.g. 2^15 = 32 mebibytesc
const min_parallelism = 1;

/**
* Modus to calculate the Argon2 Hash (see https://en.wikipedia.org/wiki/Argon2)
*/
export enum Argon2Modus {
    Argon2_d= 0,
    Argon2_i= 1,
    Argon2_id= 2
}

/**
 * Parameters for the Argon2 hash algorithm
 * t_cost time cost: number of iterations
 * m_cost memory usage: memory usage of 2^N KiB
 * parallelism: number of threasds to use
 * 
 * Note: There is a trade-off between t_cost and m_cost 
 * 
 */
export interface Argon2Parameters {
    t_cost: number,
    m_cost: number,
    parallelism: number
}

/**
 * Result types of the validation of Argon2Parameters
 */
export enum Argon2ParameterValidationResultType {
    OK=0,
    PARAMETER_INCOMPLETE=-1, // one of the parameters is undefined
    PARAMETER_NOT_MINIMAL_SECURE=-2 // one of the parameters does not correspond to minimal security requirements
}

/**
 * Result of the validation of Argon2Parameters
 */
export interface Argon2ParameterValidationResult {
    parameterName: string,
    parameterResult: Argon2ParameterValidationResultType
}

/**
 * Result type of the verification of a Argon2 hash
 */
export enum Argon2VerifyResult {
    OK=0,
    OUTPUT_PTR_NULL=-1,
    OUTPUT_TOO_SHORT = -2,
    OUTPUT_TOO_LONG = -3,
    PWD_TOO_SHORT = -4,
    PWD_TOO_LONG = -5,
    SALT_TOO_SHORT = -6,
    SALT_TOO_LONG = -7,
    AD_TOO_SHORT = -8,
    AD_TOO_LONG = -9,
    SECRET_TOO_SHORT = -10,
    SECRET_TOO_LONG = -11,
    TIME_TOO_SMALL = -12,
    TIME_TOO_LARGE = -13,
    MEMORY_TOO_LITTLE = -14,
    MEMORY_TOO_MUCH = -15,
    LANES_TOO_FEW = -16,
    LANES_TOO_MANY = -17,
    PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
    SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
    SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
    AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */
    MEMORY_ALLOCATION_ERROR = -22,
    FREE_MEMORY_CBK_NULL = -23,
    ALLOCATE_MEMORY_CBK_NULL = -24,
    INCORRECT_PARAMETER = -25,
    INCORRECT_TYPE = -26,
    OUT_PTR_MISMATCH = -27,
    THREADS_TOO_FEW = -28,
    THREADS_TOO_MANY = -29,
    MISSING_ARGS = -30,
    ENCODING_FAIL = -31,
    DECODING_FAIL = -32,
    THREAD_FAIL = -33,
    DECODING_LENGTH_FAIL = -34,
    VERIFY_MISMATCH = -35
}

/**
 * Calculate and verify Argon2 hashes using the original Argon2 C library  (https://github.com/P-H-C/phc-winner-argon2) compiled to WASM
 * 
 */
export class Argon2 {
    private argon2Module: Argon2Module;

    /**
     * Load the Argon2 wasm module
     */
    constructor() {
        this.argon2Module=create_argon2_module();
    }

    /**
     * Calculates the Argon 2d hash of the password and the salt
     * 
     * @param pwd password to hash. Please make sure it is truely random
     * @param salt salt for the password. Please make sure it is truely random
     * @param size of the returned hash in bytes
     * @param parameters parameters for adapting the security properties of the calculated hash
     * 
     * @returns hash including settings to easily verify it ("encoded" variant)
     */
    public argon2d_hash(pwd: string, salt: string, size: number, parameters?: Argon2Parameters): string {
        return this.argon2_hash(pwd,salt,Argon2Modus.Argon2_d,size, parameters);
    }

    /**
     * Calculates the Argon 2i hash of the password and the salt
     * 
     * @param pwd password to hash. Please make sure it is truely random
     * @param salt salt for the password. Please make sure it is truely random
     * @param size of the returned hash in bytes
     * @param parameters parameters for adapting the security properties of the calculated hash
     * 
     * @returns hash including settings to easily verify it ("encoded" variant)
     */
    public argon2i_hash(pwd: string, salt: string, size: number, parameters?: Argon2Parameters): string {
        return this.argon2_hash(pwd,salt,Argon2Modus.Argon2_i,size,parameters);
    }
     /**
     * Calculates the Argon 2id hash of the password and the salt
     * 
     * @param pwd password to hash. Please make sure it is truely random
     * @param salt salt for the password. Please make sure it is truely random
     * @param size of the returned hash in bytes
     * @param parameters parameters for adapting the security properties of the calculated hash
     * 
     * @returns hash including settings to easily verify it ("encoded" variant)
     */
    public argon2id_hash(pwd: string, salt: string, size: number, parameters?: Argon2Parameters): string {
        return this.argon2_hash(pwd,salt,Argon2Modus.Argon2_id,size,parameters);
    }

    /**
     * Calculates the Argon hash of the password and the salt
     * 
     * @param pwd password to hash. Please make sure it is truely random
     * @param salt salt for the password. Please make sure it is truely random
     * @param modus Argon2 modus to calculate the hash
     * @param size of the returned hash in bytes
     * @param parameters parameters for adapting the security properties of the calculated hash
     * 
     * @returns hash including settings to easily verify it ("encoded" variant)
     */
    public argon2_hash(pwd: string, salt: string, modus: Argon2Modus, size: number, parameters?: Argon2Parameters): string {
        // check pwd
        if (pwd.length<min_pwd_length) {
            throw new Error (`Password of length ${pwd.length} does not correspond to minimal security settings.`)
        }
        // check salt
        if (salt.length<min_salt_length) {
            throw new Error (`Salt of length ${salt.length} does not correspond to minimal security settings.`)
        }
        // check parameters
        let t_cost = min_t_cost;
        let m_cost = min_m_cost;
        let parallelism = min_parallelism;
        let validatedParameters: Argon2ParameterValidationResult[] = this.validateParameters(parameters);
        for (let validatedParameter  of validatedParameters) {
            if (validatedParameter.parameterResult!==Argon2ParameterValidationResultType.OK) {
              if  (validatedParameter.parameterResult===Argon2ParameterValidationResultType.PARAMETER_NOT_MINIMAL_SECURE) {
                 throw new Error (`Parameter ${validatedParameter.parameterName} does not fulfill minimal security settings.`)
              } 
            } else {
                switch(validatedParameter.parameterName) { 
                    case "t_cost": { 
                       t_cost=parameters?.t_cost as number;
                       break; 
                    } 
                    case "m_cost": { 
                        m_cost=parameters?.m_cost as number;
                       break; 
                    } 
                    case "parallelism": { 
                        parallelism=parameters?.parallelism as number;
                        break; 
                     } 
                    default: { 
                        throw new Error (`Unknown Parameter ${validatedParameter.parameterName}`);
                       break; 
                    } 
                 } 
                 

            }
        }
  
       return this.argon2Module.wasm_argon2_hash(pwd,salt,modus,t_cost,m_cost,parallelism,size);
    }

    /**
     * Verify an Argon2d hash
     * 
     * @param hash Argon2 hash to verify. Note: Must contain the settings and the hash encoded as produced by the hash functions in this class ("encoded" variant)
     * @param pwd Password used to base the hash on
     * 
     * @returns outcome of the verification
     */
    public argon2d_verify(hash:string, pwd:string): Argon2VerifyResult {
        return this.argon2Module.wasm_argon2_verify(hash,pwd,Argon2Modus.Argon2_d);
    }

    /**
     * Verify an Argon2i hash
     * 
     * @param hash Argon2 hash to verify. Note: Must contain the settings and the hash encoded as produced by the hash functions in this class ("encoded" variant)
     * @param pwd Password used to base the hash on
     * 
     * @returns outcome of the verification
     */
    public argon2i_verify(hash:string, pwd:string): Argon2VerifyResult {
        return this.argon2Module.wasm_argon2_verify(hash,pwd,Argon2Modus.Argon2_i);
    }

    /**
     * Verify an Argon2id hash
     * 
     * @param hash Argon2 hash to verify. Note: Must contain the settings and the hash encoded as produced by the hash functions in this class ("encoded" variant)
     * @param pwd Password used to base the hash on
     * 
     * @returns outcome of the verification
     */
    public argon2id_verify(hash:string, pwd:string): Argon2VerifyResult {
        return this.argon2Module.wasm_argon2_verify(hash,pwd,Argon2Modus.Argon2_id);
    }

    /**
     * Verify an Argon hash
     * 
     * @param hash Argon2 hash to verify. Note: Must contain the settings and the hash encoded as produced by the hash functions in this class ("encoded" variant)
     * @param pwd Password used to base the hash on
     * @param modus Argon2 modus to calculate the hash
     * 
     * @returns outcome of the verification
     */
    public argon2_verify(hash:string, pwd:string, modus: Argon2Modus): Argon2VerifyResult {
        return this.argon2Module.wasm_argon2_verify(hash,pwd,modus);
    }

    /**
     * Validates the parameters used for the Argon2 hashing function
     * 
     * @param parameters parameters to validate
     * 
     * @returns validation results
     */
    private validateParameters(parameters?: Argon2Parameters): Argon2ParameterValidationResult[] {
        let result: Argon2ParameterValidationResult[] = [];
        
        if (parameters===undefined) {
            let t_cost_result: Argon2ParameterValidationResult =    { parameterName: "t_cost", parameterResult: Argon2ParameterValidationResultType.PARAMETER_INCOMPLETE};
            let m_cost_result: Argon2ParameterValidationResult =    { parameterName: "m_cost", parameterResult: Argon2ParameterValidationResultType.PARAMETER_INCOMPLETE};
            let parallelism: Argon2ParameterValidationResult =    { parameterName: "parallelism", parameterResult: Argon2ParameterValidationResultType.PARAMETER_INCOMPLETE};
            result.push(t_cost_result);
            result.push(m_cost_result);
            result.push(parallelism);
        } else {
            let t_cost_parameterResult: Argon2ParameterValidationResultType = Argon2ParameterValidationResultType.PARAMETER_INCOMPLETE;
            if ((parameters.t_cost!==undefined) && (parameters.t_cost >= min_t_cost)) {
                t_cost_parameterResult=Argon2ParameterValidationResultType.OK;
            } else {
                t_cost_parameterResult=Argon2ParameterValidationResultType.PARAMETER_NOT_MINIMAL_SECURE;
            }
            let t_cost_result: Argon2ParameterValidationResult =    { parameterName: "t_cost", parameterResult: t_cost_parameterResult};
            let m_cost_parameterResult: Argon2ParameterValidationResultType = Argon2ParameterValidationResultType.PARAMETER_INCOMPLETE;
            if ((parameters.m_cost!==undefined) && (parameters.m_cost >= min_m_cost)) {
                m_cost_parameterResult=Argon2ParameterValidationResultType.OK;
            } else {
                m_cost_parameterResult=Argon2ParameterValidationResultType.PARAMETER_NOT_MINIMAL_SECURE;
            }
            let m_cost_result: Argon2ParameterValidationResult =    { parameterName: "m_cost", parameterResult: m_cost_parameterResult};
            let parallelism_parameterResult: Argon2ParameterValidationResultType = Argon2ParameterValidationResultType.PARAMETER_INCOMPLETE;
              if ((parameters.parallelism!==undefined) && (parameters.parallelism >= min_m_cost)) {
                parallelism_parameterResult=Argon2ParameterValidationResultType.OK;
            } else {
                parallelism_parameterResult=Argon2ParameterValidationResultType.PARAMETER_NOT_MINIMAL_SECURE;
            }
            let parallelism_result: Argon2ParameterValidationResult =    { parameterName: "parallelism", parameterResult: Argon2ParameterValidationResultType.PARAMETER_INCOMPLETE};
            result.push(t_cost_result);
            result.push(m_cost_result);
            result.push(parallelism_result);
        }
        return result;
    }

}