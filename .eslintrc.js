module.exports = {
  env: {
    browser: true,
    es2021: true,
  },
  extends: [
    // ...
    'eslint:recommended',
    'prettier', // Make sure this is the last
  ],
  overrides: [
    {
      env: {
        node: true,
      },
      files: ['.eslintrc.{js,cjs}'],
      parserOptions: {
        sourceType: 'script',
      },
    },
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
}
