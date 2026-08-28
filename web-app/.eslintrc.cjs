/** @type {import('eslint').Linter.Config} */
module.exports = {
  root: true,
  extends: ['next/core-web-vitals'],
  ignorePatterns: ['.next/', 'node_modules/', 'specs/', 'public/'],
  rules: {
    '@next/next/no-img-element': 'off',
  },
};
