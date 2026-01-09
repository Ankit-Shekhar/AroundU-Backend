class ApiError extends Error {
    // using a constructor to set which fields to send when the ApiErrors constructor is called
    constructor(
        statusCode,
        message = 'An error occurred',
        errors = [],
        stack = ""
    ) {
        // overriding the default constructor fields with my custom data.
        super(message);
        this.statusCode = statusCode;
        this.data = null;
        this.message = message;
        // here we are defining ApiError not ApiResponse so if any error occurs its very obvious that the success flag will be false.
        this.success = false;
        this.errors = errors;

        // gives the stacktrace of which files have the errors, removed when pushing to production.
        if (stack) {
            this.stack = stack;
        } else {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}

export { ApiError }

// // whats the use of super(message);  answer from chatGPT:
// Why it’s required: In a class that extends another (ApiError extends Error), you must call super(...) before using this. It sets up the instance correctly so you can safely assign your own fields.

// Without it: Accessing this throws an error, and the instance won’t behave like a proper Error (wrong prototype/fields). Even if you later set this.message, you’d still miss the base Error initialization.
