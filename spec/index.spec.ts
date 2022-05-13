import {ZuCryptWebStorageService} from "../src/";

describe("Integraded ZuCryptWebStorageService test", () => {
  it("should be true", () => {
    const storageService: ZuCryptWebStorageService = new ZuCryptWebStorageService();
    expect(true).toBe(true);
  });
});
