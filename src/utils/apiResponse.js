class ApiResponse {

    // sets a consistent response structure for the controllers and overriding them with custom data. 
    constructor(statusCode, message = "Success", data) {
        this.statusCode = statusCode;
        this.message = message;
        this.data = data;
        this.success = statusCode < 400;
    }
}
export { ApiResponse }