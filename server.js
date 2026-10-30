
const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// --------------------------------------------------
// 1. HEALTH CHECK
// --------------------------------------------------

app.get('/', (req, res) => {
  res.status(200).send('Cashfree Student Bridge is running.');
});


// --------------------------------------------------
// 2. CASHFREE SIGNATURE VERIFICATION
// --------------------------------------------------

function verifyCashfreeSignature(
  timestamp,
  rawBody,
  receivedSignature,
  secret
) {
  if (!timestamp || !receivedSignature || !secret) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(timestamp + rawBody, 'utf8')
    .digest();

  let actualSignature;

  try {
    actualSignature = Buffer.from(
      receivedSignature,
      'base64'
    );
  } catch (error) {
    return false;
  }

  return (
    actualSignature.length === expectedSignature.length &&
    crypto.timingSafeEqual(
      actualSignature,
      expectedSignature
    )
  );
}


// --------------------------------------------------
// 3. HELPER: NORMALIZE CUSTOM FIELD NAMES
// --------------------------------------------------

function normalize(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}


// --------------------------------------------------
// 4. CASHFREE PAYMENT FORM WEBHOOK
// --------------------------------------------------

app.post(
  '/cashfree/payment-form',
  express.raw({ type: 'application/json', limit: '1mb' }),
  async (req, res) => {

    try {
      if (!Buffer.isBuffer(req.body)) {
        return res.status(400).send('Invalid request body.');
      }

      const rawBody = req.body.toString('utf8');

      // Read Cashfree webhook headers.
      const timestamp = req.get('x-webhook-timestamp');
      const signature = req.get('x-webhook-signature');

      const secret = process.env.CASHFREE_SECRET_KEY;

      // Verify signature BEFORE trusting payload.
      const validSignature = verifyCashfreeSignature(
        timestamp,
        rawBody,
        signature,
        secret
      );

      if (!validSignature) {
        console.error('Cashfree signature verification failed.');
        return res.status(401).send('Invalid signature.');
      }

      const event = JSON.parse(rawBody);

      // Process only Payment Form events.
      if (event.type !== 'PAYMENT_FORM_ORDER_WEBHOOK') {
        return res.status(200).send('Event ignored.');
      }

      const form = event.data?.form || {};
      const order = event.data?.order;

      if (!order) {
        return res.status(400).send('Order data missing.');
      }

      // Optional: restrict this service to your production form.
      const allowedFormId = process.env.CASHFREE_FORM_ID;

      if (allowedFormId) {
        const receivedIds = [
          form.form_id,
          form.cf_form_id
        ].map(value => String(value || ''));

        if (!receivedIds.includes(String(allowedFormId))) {
          return res.status(200).send('Different form ignored.');
        }
      }

      // Only successful payments should reach the spreadsheet.
      if (
        String(order.order_status || '').toUpperCase() !== 'PAID'
      ) {
        return res.status(200).send('Payment not successful.');
      }

      const customer = order.customer_details || {};
      const fields = customer.customer_fields || [];

      // Convert Cashfree custom fields into a lookup object.
      const customFields = {};

      fields.forEach(field => {
        customFields[normalize(field.title)] =
          String(field.value ?? '').trim();
      });

      function getCustomField(...names) {
        for (const name of names) {
          const value = customFields[normalize(name)];

          if (value) return value;
        }

        return '';
      }

      // Map the fields from your Cashfree form.
      const student = {
        name: customer.customer_name || '',
        email: customer.customer_email || '',
        phone: customer.customer_phone || '',

        domain: getCustomField(
          'Domain Name',
          'Domain'
        ),

        empCode: getCustomField(
          'Emp Code',
          'Employee Code',
          'Employee ID'
        ),

        college: getCustomField(
          'College Name',
          'College'
        ),

        paymentId: String(order.transaction_id || ''),
        orderId: String(order.order_id || ''),
        amount: Number(order.order_amount || 0),
        paymentStatus: order.order_status,
        paymentDate: event.event_time || new Date().toISOString()
      };

      if (!student.orderId || student.amount <= 0) {
        return res.status(400).send('Invalid order details.');
      }

      // --------------------------------------------------
      // 5. SEND VERIFIED DATA TO GOOGLE APPS SCRIPT
      // --------------------------------------------------

      const gasUrl = process.env.GAS_WEB_APP_URL;
      const bridgeToken = process.env.CF_BRIDGE_TOKEN;

      if (!gasUrl || !bridgeToken) {
        throw new Error('Bridge configuration is incomplete.');
      }

      const forwardResponse = await fetch(gasUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          bridgeToken: bridgeToken,
          student: student
        }),
        redirect: 'follow'
      });

      const responseText = await forwardResponse.text();

      let result;

      try {
        result = JSON.parse(responseText);
      } catch (error) {
        throw new Error(
          'Apps Script returned a non-JSON response.'
        );
      }

      if (!forwardResponse.ok || result.success !== true) {
        throw new Error(
          result.message || 'Apps Script could not save the student.'
        );
      }

      console.log(
        'Payment processed:',
        student.orderId,
        result.duplicate ? '(duplicate)' : '(new record)'
      );

      return res.status(200).send('Payment processed.');

    } catch (error) {
      console.error('Webhook processing error:', error.message);

      // Non-2xx response allows Cashfree to retry delivery.
      return res.status(500).send('Temporary processing error.');
    }
  }
);


// --------------------------------------------------
// 6. START SERVER
// --------------------------------------------------

app.listen(PORT,'0.0.0.0', () => {
  console.log(
    `Cashfree Student Bridge running on port ${PORT}`
  );
});
