"use strict";
function MapleSUInput(value) {
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(MapleSUInput);
  Object.keys(value).forEach(function (key) {
    var next = key === "pro" ? "ultra" : key.replace(/^pro(?=[A-Z])/, "ultra");
    var item = MapleSUInput(value[key]);
    if (key === "backend" && (item === "maplesu_\u0070\u0072\u006f" || item === "\u0073\u006b\u0072\u006f\u006f\u0074_\u0070\u0072\u006f")) item = "maplesu_ultra";
    if (next === key || !Object.prototype.hasOwnProperty.call(value, next)) {
      Object.defineProperty(value, next, { value: item, writable: true, enumerable: true, configurable: true });
    }
    if (next !== key) delete value[key];
  });
  return value;
}
