/**
 * End-to-End encrypted storage using official Web APIs of your browser environment
 *
 * @module
 */

/**
 * Buffers are an important concept used in this package as they do require to load and process all data in-memory - only the needed data.
 */
import { Buffer } from "buffer";

import { CapabilitiesDetector } from "./detector";

export class ZuCryptWebStorageService {
  private capabilityDetector: CapabilitiesDetector;

  constructor() {
    this.capabilityDetector = new CapabilitiesDetector();
  }

  public checkPrerequisites() {
    // todo
  }

  public createEncryptedStorage() {
    // todo
  }

  public deleteEncryptedStorage() {
    // todo
  }

  public listItems(prefix: string) {
    // todo
  }

  public putItem(location: string, itemContent: Buffer) {
    // todo
  }

  /**
   *
   * @returns Buffer from which the content can be read.
   */
  public getItem(): Buffer {
    return Buffer.from("");
  }

  public helloWorld(): string {
    return "Hello World!";
  }
}
