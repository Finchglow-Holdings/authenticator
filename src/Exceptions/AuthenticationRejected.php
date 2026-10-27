<?php

namespace Finchglow\Authenticator\Exceptions;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Extends HttpException so middleware that rethrows HttpException keeps working; render() replaces Laravel's debug page.
 */
class AuthenticationRejected extends HttpException
{
    public function __construct(int $status, string $message, private string $errorCode, private string $check, array $headers = [])
    {
        parent::__construct($status, $message, null, $headers);
    }

    public function render(): JsonResponse
    {
        return response()->json([
            'status' => false,
            'message' => $this->getMessage(),
            'error' => ['source' => 'api', 'code' => $this->errorCode, 'check' => $this->check],
        ], $this->getStatusCode(), $this->getHeaders());
    }
}
