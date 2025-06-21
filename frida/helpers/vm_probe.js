'use strict';

let _resolved = false;
const _maxAttempts = 20;
const _interval = 500;

rpc.exports = {
  wait: function () {
    return new Promise((resolve, reject) => {
      let attempts = 0;

      function checkJava() {
        if (typeof Java === "undefined" || !Java.available) {
          if (++attempts >= _maxAttempts) {
            send({ type: "jvm_unavailable", attempts });
            return reject("Java VM unavailable after retries");
          }

          if (attempts % 5 === 0) {
            send({ type: "vm_probe_status", attempts, message: "Still waiting on Java.perform()" });
          }

          return setTimeout(checkJava, _interval);
        }

        try {
          Java.perform(() => {
            if (!_resolved) {
              _resolved = true;
              send({ type: "jvm_ready", attempts });
              resolve(true);
            }
          });
        } catch (err) {
          send({ type: "vm_probe_error", attempts, message: err.message });
          reject(err);
        }
      }

      checkJava();
    });
  }
};
