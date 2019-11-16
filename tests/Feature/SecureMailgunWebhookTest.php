<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

class SecureMailgunWebhookTest extends TestCase
{

    protected function setUp() :void
    {
        parent::setUp();

        config()->set('services.mailgun.secret', 'secret');

        \Route::middleware('mailgun.webhook')->any('/_test/webhook', function () {
            return 'OK';
        });
    }

    /** @test */
    public function it_forbids_non_post_methods()
    {
        $this->withoutExceptionHandling();

        $exceptionCount = 0;
        $httpVerbs = ['get', 'put', 'patch', 'delete'];

        foreach ($httpVerbs as $httpVerb) {
            try {
                $response = $this->$httpVerb('/_test/webhook');
            } catch (HttpException $e) {
                $exceptionCount++;
                $this->assertEquals(Response::HTTP_FORBIDDEN, $e->getStatusCode());
                $this->assertEquals('Only POST requests are allowed.', $e->getMessage());
            }
        }

        if (count($httpVerbs) === $exceptionCount) {
            return;
        }

        $this->fail('Expected a 403 forbidden');
    }

    /** @test */
    public function it_aborts_with_an_invalid_signature()
    {
        $this->withoutExceptionHandling();

        try {
            $this->post('/_test/webhook', [
                'timestamp' => abs(time() - 100),
                'token' => 'invalid-token',
                'signature' => 'invalid-signature',
            ]);
        } catch (HttpException $e) {
            $this->assertEquals(Response::HTTP_FORBIDDEN, $e->getStatusCode());
            $this->assertEquals('The webhook signature was invalid.', $e->getMessage());
            return;
        }

        $this->fail('Expected the webhook signature to be invalid.');
    }

    /** @test */
    public function it_passes_with_a_valid_signature()
    {
        $this->withoutExceptionHandling();

        $timestamp = time();
        $token = 'token';
        $response = $this->post('/_test/webhook', [
            'timestamp' => $timestamp,
            'token' => $token,
            'signature' => $this->buildSignature($timestamp, $token),
        ]);

        $this->assertEquals('OK', $response->getContent());
    }

    protected function buildSignature($timestamp, $token)
    {
        return hash_hmac(
            'sha256',
            sprintf('%s%s', $timestamp, $token),
            config('services.mailgun.secret')
        );
    }

    /** @test */
    public function it_fails_with_an_old_timestamp()
    {
        try {
            $this->withoutExceptionHandling();

            $timestamp = abs(time() - 16);
            $token = 'token';
            $response = $this->post('/_test/webhook', [
                'timestamp' => $timestamp,
                'token' => $token,
                'signature' => $this->buildSignature($timestamp, $token),
            ]);
        } catch (HttpException $e) {
            $this->assertEquals(Response::HTTP_FORBIDDEN, $e->getStatusCode());
            $this->assertEquals('The webhook signature was invalid.', $e->getMessage());
            return;
        }

        $this->fail('The timestamp should have failed verification.');
    }


}
