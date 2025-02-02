<?php

namespace App\Gateways\StripeSubscriptions;

use LaraPay\Framework\Interfaces\SubscriptionGateway;
use Illuminate\Support\Facades\Http;
use LaraPay\Framework\Subscription;
use Illuminate\Http\Request;

class Gateway extends SubscriptionGateway
{
    /**
     * Unique identifier for the gateway.
     */
    protected string $identifier = 'stripe-subscriptions';

    /**
     * Version of the gateway.
     */
    protected string $version = '1.0.0';

    /**
     * The currencies supported by the gateway.
     */
    protected array $currencies = [];

    /**
     * Define the config fields required for the gateway.
     *
     * These values can be retrieved using $subscription->gateway->config('key')
     */
    public function config(): array
    {
        return [
            'secret_key' => [
                'label'       => 'Stripe Secret Key',
                'description' => 'Your Stripe Secret API Key',
                'type'        => 'text',
                'rules'       => ['required', 'string', 'starts_with:sk_'],
            ],
            'webhook_secret' => [
                'label'       => 'Stripe Webhook Secret',
                'description' => 'Your Stripe Webhook Secret',
                'type'        => 'text',
                'rules'       => ['required', 'string', 'starts_with:whsec_'],
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
        $period = $this->getOptimalInterval($subscription->frequency);

        // Prepare the request data for creating a Stripe Checkout Session
        // More docs: https://stripe.com/docs/api/checkout/sessions/create
        $data = [
            'success_url' => $subscription->callbackUrl(),
            'cancel_url'  => $subscription->cancelUrl(),
            'mode'        => 'subscription',
            'metadata'    => [
                'subscription_token' => $subscription->token,
            ],
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
                            'interval'      => $period['interval'],
                            'interval_count' => $period['frequency'],
                        ],
                    ],
                    'quantity' => 1,
                ],
            ],
            'subscription_data' => [
                'metadata' => [
                    'subscription_token' => $subscription->token,
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
     * Helps find an interval (DAY, WEEK, MONTH, YEAR) that evenly divides $days.
     */
    private function getOptimalInterval(int $days): array
    {
        $intervals = [
            365 => 'year',
            30 => 'month',
            7 => 'week',
            1 => 'day',
        ];

        // Pick the largest interval that cleanly divides $days
        foreach ($intervals as $dayEquivalent => $label) {
            if ($days % $dayEquivalent === 0) {
                return [
                    'frequency' => $days / $dayEquivalent,
                    'interval'  => $label
                ];
            }
        }

        // Fallback (shouldn't usually happen unless you have weird intervals)
        return ['frequency' => 1, 'interval' => 'day'];
    }

    /**
     * Handle the callback/return URL from Stripe after a successful checkout.
     */
    public function callback(Request $request)
    {
        $token     = $request->query('subscription_token'); // or however your system tracks subscription tokens

        // Retrieve local subscription by token
        $subscription = Subscription::where('token', $token)->first();
        if (! $subscription) {
            throw new \Exception('Subscription not found');
        }

        $sessionId = $subscription->subscription_id;

        // check if the session id starts with cs_ to know if it is a checkout session
        if (strpos($sessionId, 'cs_') !== 0) {

            // if starts with sub_ and assume the webhook has already taken care of the subscription
            if(strpos($sessionId, 'sub_') === 0) {
                return redirect($subscription->successUrl());
            }

            throw new \Exception('Invalid Stripe Checkout Session ID');
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

                // set the due date for the subscription
                $subscription->update([
                    'expires_at' => $stripeSubscriptionResponse['current_period_end'],
                ]);
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

        $eventType = $eventData['type'] ?? null;

        // get the subscription token from the metadata
        $subscriptionToken = $eventData['data']['object']['metadata']['subscription_token'];
        $subscription = Subscription::where('token', $subscriptionToken)->first();

        if (! $subscription) {
            throw new \Exception('Subscription not found');
        }

        // Verify the webhook signature
        $this->verifyStripeWebhook($subscription->gateway->config('webhook_secret'));

        switch ($eventType) {
            case 'customer.subscription.created':
            case 'customer.subscription.updated':
                $subscriptionObject = $eventData['data']['object'];

                // If the subscription is active or trialing, mark it as active in your system
                if (in_array($subscriptionObject['status'], ['active', 'trialing'])) {
                    // ensure subscription is not already active
                    if ($subscription->isActive()) {
                        return response()->json(['status' => 'ok'], 200);
                    }

                    $subscription->activate($subscriptionObject['id'], $subscriptionObject);

                    // set the due date for the subscription
                    $subscription->update([
                        'expires_at' => $subscriptionObject['current_period_end'],
                    ]);
                }

                break;
            case 'customer.subscription.deleted':
            // You can handle more Stripe events if desired
            default:
                // Ignore other events
                break;
        }

        return response()->json(['status' => 'ok'], 200);
    }

    private function verifyStripeWebhook($webhookSecret)
    {
        // Get the raw request body
        $payload = file_get_contents('php://input');

        // Retrieve the Stripe signature header
        $sigHeader = $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? null;

        if (!$sigHeader) {
            throw new \Exception("Stripe signature header is missing.");
        }

        // Parse the Stripe signature header
        $timestamp = null;
        $signature = null;
        foreach (explode(',', $sigHeader) as $part) {
            list($key, $value) = explode('=', trim($part), 2);
            if ($key === 't') {
                $timestamp = $value;
            } elseif ($key === 'v1') {
                $signature = $value;
            }
        }

        if (!$timestamp || !$signature) {
            throw new \Exception("Invalid Stripe signature header format.");
        }

        // Compute the expected signature
        $signedPayload = $timestamp . '.' . $payload;
        $expectedSignature = hash_hmac('sha256', $signedPayload, $webhookSecret);

        // Compare the computed signature with the Stripe-provided signature
        if (!hash_equals($expectedSignature, $signature)) {
            throw new \Exception("Invalid Stripe webhook signature.");
        }

        return json_decode($payload, true); // Return the webhook event as an array
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
