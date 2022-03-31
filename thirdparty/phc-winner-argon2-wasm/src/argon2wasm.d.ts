/// <reference types="emscripten" />
/** Above will import declarations from @types/emscripten, including Module etc. */
// This will merge to the existing EmscriptenModule interface from @types/emscripten
// If this doesn't work, try globalThis.EmscriptenModule instead.

export interface Argon2Module extends EmscriptenModule {
  wasm_argon2_hash(
    pwd: string,
    salt: string,
    modus: number,
    t_cost: number,
    m_cost: number,
    parallelism: number,
    size: number
  ): string;
  wasm_argon2_verify(hash: string, pwd: string, modus: number): number;
}

export default function create_argon2_module(mod?: any): Argon2Module;
