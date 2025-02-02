<?php

namespace App\Gateways\StripeSubscriptionGateway;

use LaraPay\Framework\Interfaces\SubscriptionGateway;
use Illuminate\Support\Facades\Http;
use LaraPay\Framework\Subscription;
use Illuminate\Http\Request;

class Gateway extends SubscriptionGateway
{
    /**
     * Unique identifier for the gateway.
     */
    protected string $identifier = 'stripe-subscription-gateway';

    /**
     * Version of the gateway.
     */
    protected string $version = '1.0.0';

    /**
     * The currencies supported by the gateway.
     */
    protected array $currencies = [
        'USD',
        'EUR',
        // etc...
    ];

    /**
     * Define the config fields required for the gateway.
     *
     * These values can be retrieved using $subscription->gateway->config('key')
     */
    public function config(): array
    {
        return [
            'mode' => [
                'label'       => 'Mode (Test/Live)',
                'description' => 'Use test mode for testing or live for production',
                'type'        => 'select',
                'options'     => ['test' => 'Test', 'live' => 'Live'],
                'rules'       => ['required'],
            ],
            'secret_key' => [
                'label'       => 'Stripe Secret Key',
                'description' => 'Your Stripe Secret API Key',
                'type'        => 'text',
                'rules'       => ['required', 'string'],
            ],
            // Add other fields as needed (e.g., publishable key, webhook secret, etc.)
        ];
    }

    /**
     * Main entry point for creating a subscription and redirecting to Stripe Checkout.
     *
     * In this method, we create a Checkout Session for a subscription,
     * then redirect the user to complete the payment on Stripe.
     */
    public function subscribe($subscription)
    {
        // Retrieve config
        $secretKey = $subscription->gateway->config('secret_key');
        $amountInCents = (int) ($subscription->amount * 100);

        // Prepare the request data for creating a Stripe Checkout Session
        // More docs: https://stripe.com/docs/api/checkout/sessions/create
        $data = [
            'success_url' => $subscription->callbackUrl(['session_id' => '{CHECKOUT_SESSION_ID}']),
            'cancel_url'  => $subscription->cancelUrl(),
            'mode'        => 'subscription',
            'line_items'  => [
                [
                    'price_data' => [
                        'currency'     => $subscription->currency,
                        'product_data' => [
                            'name' => $subscription->name,
                        ],
                        'unit_amount' => $amountInCents,
                        // For recurring intervals, see https://stripe.com/docs/billing/subscriptions/products-and-prices#pricing
                        'recurring' => [
                            // You can map $subscription->frequency (days) to an interval here.
                            // For simplicity, let's assume a daily frequency if $subscription->frequency = 1 day
                            'interval'      => 'day',
                            'interval_count' => $subscription->frequency,
                        ],
                    ],
                    'quantity' => 1,
                ],
            ],
        ];

        // Make the HTTP POST request to create a Checkout Session
        $response = Http::withBasicAuth($secretKey, '')
            ->asForm() // Stripe expects form-encoded by default
            ->post('https://api.stripe.com/v1/checkout/sessions', $data);

        if ($response->failed()) {
            throw new \Exception('Failed to create Stripe Checkout Session: ' . $response->body());
        }

        $sessionData = $response->json();

        // Store the checkout session ID so we can retrieve it later on callback
        $subscription->update([
            'subscription_id' => $sessionData['id'], // This is the Checkout Session ID, not the final subscription ID
        ]);

        // Redirect the user to the Stripe Checkout URL
        return redirect()->away($sessionData['url']);
    }

    /**
     * Handle the callback/return URL from Stripe after a successful checkout.
     */
    public function callback(Request $request)
    {
        // We expect Stripe to redirect back with ?session_id={CHECKOUT_SESSION_ID} on success
        $sessionId = $request->query('session_id');
        $token     = $request->query('subscription_token'); // or however your system tracks subscription tokens

        // Retrieve local subscription by token
        $subscription = Subscription::where('token', $token)->first();
        if (! $subscription) {
            throw new \Exception('Subscription not found');
        }

        // Retrieve the Checkout Session from Stripe to verify subscription status
        $secretKey = $subscription->gateway->config('secret_key');
        $checkoutSessionResponse = Http::withBasicAuth($secretKey, '')
            ->get("https://api.stripe.com/v1/checkout/sessions/{$sessionId}");

        if ($checkoutSessionResponse->failed()) {
            throw new \Exception('Failed to retrieve Stripe Checkout Session: ' . $checkoutSessionResponse->body());
        }

        $checkoutSession = $checkoutSessionResponse->json();

        // The Checkout Session includes a 'subscription' field once the user completes payment
        if (! empty($checkoutSession['subscription'])) {
            $stripeSubscriptionId = $checkoutSession['subscription'];

            // Update your local record so we know the actual Stripe Subscription ID
            $subscription->update([
                'subscription_id' => $stripeSubscriptionId,
            ]);

            // Optionally fetch the full subscription info to check its status
            $stripeSubscriptionResponse = Http::withBasicAuth($secretKey, '')
                ->get("https://api.stripe.com/v1/subscriptions/{$stripeSubscriptionId}")
                ->json();

            // If the subscription is "active" or "trialing", mark it active in your system
            if (in_array($stripeSubscriptionResponse['status'], ['active','trialing'])) {
                $subscription->activate($stripeSubscriptionId, $stripeSubscriptionResponse);
            }
        }

        // Redirect to your own "post-checkout" page or wherever you want the user to land
        return redirect($subscription->successUrl());
    }

    /**
     * Handle webhooks from Stripe (e.g., subscription updated, canceled, etc.).
     *
     * Be sure to set up your webhook endpoint in Stripe’s dashboard and verify
     * signatures for security in a real-world environment.
     */
    public function webhook(Request $request)
    {
        // Stripe sends JSON in the request body
        $eventData = $request->json()->all();

        // For real production usage, verify the signature:
        // $signature = $request->header('Stripe-Signature');
        // ... then use that to check with your webhook secret.

        $eventType = $eventData['type'] ?? null;
        $object    = $eventData['data']['object'] ?? [];

        switch ($eventType) {
            case 'customer.subscription.created':
            case 'customer.subscription.updated':
            case 'customer.subscription.deleted':
                $stripeSubscriptionId = $object['id'];
                $status = $object['status'];

                // Find your local subscription record by the Stripe subscription ID
                $subscription = Subscription::where('subscription_id', $stripeSubscriptionId)->first();

                if ($subscription) {
                    if (in_array($status, ['active', 'trialing'])) {
                        $subscription->activate($stripeSubscriptionId, $object);
                    } elseif ($status === 'canceled') {
                        $subscription->cancel();
                        // or $subscription->deactivate() depending on how your system handles it
                    }
                    // handle other statuses if needed (e.g. 'past_due', 'incomplete', etc.)
                }
                break;

            // You can handle more Stripe events if desired
            default:
                // Ignore other events
                break;
        }

        return response()->json(['status' => 'ok'], 200);
    }

    /**
     * Check if a subscription is still ACTIVE on Stripe.
     *
     * Called periodically (e.g., every 12 hours) to verify status.
     */
    public function checkSubscription($subscription): bool
    {
        $secretKey = $subscription->gateway->config('secret_key');
        $stripeSubscriptionId = $subscription->subscription_id;

        // Retrieve the subscription from Stripe
        $response = Http::withBasicAuth($secretKey, '')
            ->get("https://api.stripe.com/v1/subscriptions/{$stripeSubscriptionId}");

        if ($response->failed()) {
            return false;
        }

        $stripeSub = $response->json();
        return in_array($stripeSub['status'], ['active', 'trialing']);
    }

    /**
     * Cancel a subscription on Stripe.
     */
    public function cancelSubscription($subscription): bool
    {
        $secretKey = $subscription->gateway->config('secret_key');
        $stripeSubscriptionId = $subscription->subscription_id;

        // Stripe cancels a subscription with a DELETE or a POST (depending on desired behavior).
        // If you want to cancel immediately:
        $response = Http::withBasicAuth($secretKey, '')
            ->delete("https://api.stripe.com/v1/subscriptions/{$stripeSubscriptionId}");

        // If you prefer to cancel at period end, you could do:
        // ->post("https://api.stripe.com/v1/subscriptions/{$stripeSubscriptionId}", [
        //     'cancel_at_period_end' => true
        // ]);

        if ($response->failed()) {
            return false;
        }

        return true;
    }
}