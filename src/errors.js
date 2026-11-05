/** An error that is safe to show to the client. Anything else becomes a generic 500. */
export class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
    this.expose = true;
  }
}

/** The uploaded bytes failed validation (wrong type, corrupt, too large, unsafe...). */
export class UploadRejected extends HttpError {
  constructor(code, message) {
    super(422, code, message);
  }
}

export const notFound = () => new HttpError(404, 'not_found', 'Not found');
