/**
 * DTO layer — the single seam where DB rows / raw SQL results are shaped
 * into the API contract the dashboard sees.
 *
 * Add a new entity's DTO here as `<entity>.ts`, re-export from this index,
 * and call the `to<Entity>DTO()` function from your route handler. Do not
 * coerce postgres-native types (numeric strings, bigints) anywhere else.
 */

export * from './common';
export * from './pagination';
export * from './vulnerability';
export * from './landscape';
