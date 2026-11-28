// Dev-only: tsx registers its module hooks on the main thread only, so a worker
// that loads this package's TypeScript sources starts with no loader and dies on
// the first relative `.js` specifier. Registering here — before the worker's
// entry module is loaded — gives the thread the same resolution the parent has.
// The built worker (dist) needs none of this: tsup inlines every relative import.
import { register } from 'tsx/esm/api'
register()
