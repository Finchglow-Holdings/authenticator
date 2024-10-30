# Finchglow Authenticator Package

The `finchglow/authenticator` package provides several middleware for client authentication, permission checking, JWT authentication, and retrieving user data in Laravel applications. This package is easily configurable and allows you to add security and permission layers to your API or web application.

## Features

- **AuthenticateClientMiddleware:** Verifies client authentication based on the provided client key.
- **CheckPermissionMiddleware:** Ensures that the user has the required permissions to perform specific actions.
- **GetUserMiddleware:** Retrieves and validates the current user data.
- **JwtAuthMiddleware:** Handles JWT token authentication for secure API requests.

## Installation

### Step 1: Install via Composer

Run the following command to install the package:

```bash
composer require finchglow/authenticator
```

## Middleware Overview

1. **`auth-client-key`**  
   This middleware checks the client authentication key and ensures it's valid before proceeding with the request.
   - **Usage:**
     ```php
     Route::middleware(['auth-client-key'])->group(function () {
         // Your routes
     });
     ```

2. **`check-permission`**  
   Ensures that the authenticated user has the required permissions.
   - **Usage:**
     ```php
     Route::middleware(['check-permission:name of permission'])->group(function () {
         // Your routes
     });
     ```

3. **`get-user`**  
   This middleware retrieves the current user and attaches it to the request.
   - **Usage:**
     ```php
     Route::middleware(['get-user'])->group(function () {
         // Your routes
     });
     ```

4. **`jwt-auth`**  
   Validates the JWT token passed with the request and authenticates the user.
   - **Usage:**
     ```php
     Route::middleware(['jwt-auth:user_type'])->group(function () {
         // Your routes
     });
     ```

## Configuration

After publishing the configuration file, you can configure your authenticator settings in `config/authenticator.php`. This includes settings like:

- **API Key Validation**: Customize client API key rules.
- **Permission Settings**: Set up how permissions are managed.
- **JWT Authentication**: Define your JWT secret, expiration, and other settings.

## Example Usage

Here’s an example of how you might use these middleware in your routes:

```php
use Illuminate\Support\Facades\Route;

Route::middleware(['auth-client-key', 'jwt-auth:admin', 'check-permission:create airport', 'get-user'])->group(function () {
    Route::get('/protected-resource', [SomeController::class, 'someMethod']);
});
```

This will ensure that:
1. The client key is validated.
2. The user is authenticated via a JWT token.
3. The user's permissions are checked.
4. The user data is available in the request.

## License

This package is open-source and distributed under the MIT License. Feel free to modify it to suit your needs.

---

This README provides a clear guide on how to install, configure, and use the `finchglow/authenticator` package. You can further expand it with more details if needed, such as example configurations or additional features.
