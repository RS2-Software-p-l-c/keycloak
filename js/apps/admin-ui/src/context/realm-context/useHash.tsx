import { useEffect, useState } from "react";

export const useHash = () => {
  const [hash, setHash] = useState(location.hash);

  useEffect(() => {
    const orgPushState = window.history.pushState;
    window.history.pushState = new Proxy(window.history.pushState, {
      apply: (func, target, args) => {
        const urlArg = args[2]

        // Create a URL object to safely parse the input
        // We use window.location.origin as the base in case urlArg is relative (e.g. "/path" or "#hash")
        const url = new URL(urlArg, window.location.origin)

        // Extract the hash and remove the leading '#'
        setHash(decodeURIComponent(url.hash.substring(1)))
        return Reflect.apply(func, target, args);
      },
    });
    return () => {
      window.history.pushState = orgPushState;
    };
  }, []);
  return hash;
};
