module.exports = async () => {
  return {
    preset: "ts-jest",
    testPathIgnorePatterns: ["__helpers__"],
    testEnvironment: "node",
    transform: {
      "\\.[jt]sx?$": [
        'ts-jest',
        {
          tsconfig: 'tsconfig.test.json',
        },
    ],
  }};
};
