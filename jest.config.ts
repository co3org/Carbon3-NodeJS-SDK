import type { Config } from 'jest';

const jestConfig: Config = {
  globals: {
    'ts-jest': {
      isolatedModules: true,
    },
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx'],
  transform: {
    '\\.jsx?$': 'babel-jest',
    '\\.tsx?$': 'ts-jest',
  },
  roots: ['./tests'],
  testMatch: ['./**/*.test.*'],
  automock: false,
  testTimeout: 60000,
  reporters: ['default', 'jest-junit'],
  preset: 'ts-jest',
  testEnvironment: 'node',
};
export default jestConfig;
