<?php

namespace Finchglow\Authenticator\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class StripClientCompanyDetails
{
    public function handle(Request $request, Closure $next): Response
    {
        $request->query->remove('company_details');
        $request->request->remove('company_details');
        $request->files->remove('company_details');

        if ($request->isJson()) {
            $request->json()->remove('company_details');
        }

        return $next($request);
    }
}
