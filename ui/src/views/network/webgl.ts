/**
 * True when the webview can create a WebGL context (sigma draws with WebGL2, or WebGL 1). Some
 * Linux webviews run without GPU acceleration; the view then lists the links instead of drawing
 * a blank canvas.
 */
export function hasWebGL(): boolean {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') ?? canvas.getContext('webgl');
    return gl !== null;
  } catch {
    return false;
  }
}
