
const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const WEBHOOK_PATH = '/cashfree/payment-form';
const EXPECTED_EVENT = 'PAYMENT_FORM_ORDER_WEBHOOK';

// --------------------------------------------------
// 1. REQUEST LOGGING
// --------------------------------------------------

app.use((req, res, next) => {
  console.log(`[INCOMING REQUEST] ${req.method} ${req.path}`);

  res.on('finish', () => {
    console.log(
      `[RESPONSE] ${req.method} ${req.path} - ${res.statusCode}`
    );
  });

  next();
});

// --------------------------------------------------
// 2. HEALTH CHECKS
// --------------------------------------------------

app.get('/', (req, res) => {
  res.status(200).send('Cashfree Student Bridge is running.');
});

app.get(WEBHOOK_PATH, (req, res) => {
  res.status(200).send(
    'Cashfree Payment Form webhook endpoint is ready.'
  );
});

// --------------------------------------------------
// 3. CASHFREE SIGNATURE VERIFICATION
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

  try {
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(timestamp + rawBody, 'utf8')
      .digest();

    const actualSignature = Buffer.from(
      receivedSignature,
      'base64'
    );

    return (
      actualSignature.length === expectedSignature.length &&
      crypto.timingSafeEqual(
        actualSignature,
        expectedSignature
      )
    );
  } catch (error) {
    return false;
  }
}

// --------------------------------------------------
// 4. FIELD HELPERS
// --------------------------------------------------

function normalize(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function getCustomField(fields, ...labels) {
  if (!Array.isArray(fields)) {
    return '';
  }

  const wantedLabels = labels.map(normalize);

  for (const field of fields) {
    const fieldLabel = normalize(
      field.title ??
      field.label ??
      field.field_name ??
      field.name ??
      ''
    );

    if (wantedLabels.includes(fieldLabel)) {
      return String(
        field.value ??
        field.field_value ??
        field.answer ??
        ''
      ).trim();
    }
  }

  return '';
}

// --------------------------------------------------
// 5. CASHFREE PAYMENT FORM WEBHOOK
// --------------------------------------------------

app.post(
  WEBHOOK_PATH,
  express.raw({
    type: 'application/json',
    limit: '1mb'
  }),
  async (req, res) => {
    try {
      // A. Validate raw request body

      if (!Buffer.isBuffer(req.body)) {
        return res.status(400).send(
          'Invalid webhook request body.'
        );
      }

      const rawBody = req.body.toString('utf8');

      // B. Read Cashfree signature headers

      const timestamp = req.get('x-webhook-timestamp');
      const signature = req.get('x-webhook-signature');

      const secret = process.env.CASHFREE_SECRET_KEY;

      if (!timestamp || !signature || !secret) {
        console.error('[SIGNATURE ERROR]', {
          timestampPresent: Boolean(timestamp),
          signaturePresent: Boolean(signature),
          secretConfigured: Boolean(secret)
        });

        return res.status(401).send(
          'Missing webhook verification information.'
        );
      }

      // C. Verify signature

      const validSignature = verifyCashfreeSignature(
        timestamp,
        rawBody,
        signature,
        secret
      );

      if (!validSignature) {
        console.error(
          '[SIGNATURE ERROR] Verification failed.'
        );

        return res.status(401).send(
          'Invalid Cashfree webhook signature.'
        );
      }

      console.log('[SIGNATURE SUCCESS] Verified.');

      // D. Parse verified event

      let event;

      try {
        event = JSON.parse(rawBody);
      } catch (error) {
        return res.status(400).send(
          'Invalid JSON payload.'
        );
      }

      const data = event.data || {};
      const form = data.form || {};
      const order = data.order || {};
      const payment = data.payment || {};

      console.log('[CASHFREE EVENT]', {
        eventType: event.type || 'Missing',
        formId: form.form_id || '',
        cashfreeFormId: form.cf_form_id || '',
        orderIdPresent: Boolean(order.order_id),
        orderStatus: order.order_status || '',
        paymentStatus: payment.payment_status || ''
      });

      // E. Check event type

      if (event.type !== EXPECTED_EVENT) {
        console.log('[IGNORED] Unexpected event.');

        return res.status(200).send(
          'Event ignored.'
        );
      }

      if (!order.order_id) {
        return res.status(400).send(
          'Cashfree Order ID missing.'
        );
      }

      // F. Check the configured Cashfree form ID

      const allowedFormId = String(
        process.env.CASHFREE_FORM_ID || ''
      ).trim();

      const receivedFormIds = [
        form.form_id,
        form.cf_form_id,
        data.form_id,
        data.cf_form_id
      ]
        .filter(value =>
          value !== undefined &&
          value !== null &&
          String(value).trim() !== ''
        )
        .map(value => String(value).trim());

      if (
        allowedFormId &&
        !receivedFormIds.includes(allowedFormId)
      ) {
        console.warn('[IGNORED] Form ID mismatch.');

        return res.status(200).send(
          'Different form ignored.'
        );
      }

      // G. Only process successful payments

      const orderStatus = String(
        order.order_status || ''
      ).toUpperCase();

      const paymentStatus = String(
        payment.payment_status || ''
      ).toUpperCase();

      const paymentSuccessful =
        orderStatus === 'PAID' ||
        paymentStatus === 'SUCCESS';

      if (!paymentSuccessful) {
        console.log('[IGNORED] Payment not successful.');

        return res.status(200).send(
          'Payment not successful.'
        );
      }

      // H. Extract customer information

      const customer =
        order.customer_details ||
        data.customer_details ||
        {};

      const fields =
        customer.customer_fields ||
        order.customer_fields ||
        data.customer_fields ||
        form.customer_fields ||
        [];

      // Log field labels only, never customer values.

      if (Array.isArray(fields)) {
        console.log(
          '[FORM FIELD LABELS]',
          fields.map(field =>
            field.title ||
            field.label ||
            field.field_name ||
            field.name ||
            'Unknown'
          )
        );
      }

      // I. Match the six actual Cashfree form fields

      const student = {
        // Customer details
        phone: String(
          customer.customer_phone || ''
        ).trim(),

        email: String(
          customer.customer_email || ''
        ).trim(),

        name: String(
          customer.customer_name || ''
        ).trim(),

        // Custom form fields
        domain: getCustomField(
          fields,
          'DOMAIN',
          'Domain',
          'Domain Name'
        ),

        empCode: getCustomField(
          fields,
          'EM CODE',
          'Emp Code',
          'Employee Code',
          'Employee ID'
        ),

        startDate: getCustomField(
          fields,
          'START DATE',
          'Start Date'
        ),

        // Payment details
        orderId: String(order.order_id),

        amount: Number(
          order.order_amount ??
          payment.payment_amount ??
          0
        ),

        paymentStatus: 'PAID',

        paymentDate:
          event.event_time ||
          new Date().toISOString()
      };

      // J. Validate all required form fields

      const missingFields = [];

      if (!student.phone) missingFields.push('Phone Number');
      if (!student.email) missingFields.push('Email ID');
      if (!student.name) missingFields.push('Name');
      if (!student.domain) missingFields.push('DOMAIN');
      if (!student.empCode) missingFields.push('EM CODE');
      if (!student.startDate) missingFields.push('START DATE');

      console.log('[STUDENT FIELD CHECK]', {
        phonePresent: Boolean(student.phone),
        emailPresent: Boolean(student.email),
        namePresent: Boolean(student.name),
        domainPresent: Boolean(student.domain),
        empCodePresent: Boolean(student.empCode),
        startDatePresent: Boolean(student.startDate),
        missingFields
      });

      if (missingFields.length > 0) {
        console.error(
          '[ERROR] Required form fields missing.'
        );

        return res.status(400).send(
          'Required form fields missing.'
        );
      }

      if (
        !Number.isFinite(student.amount) ||
        student.amount <= 0
      ) {
        return res.status(400).send(
          'Invalid payment amount.'
        );
      }

      // K. Forward verified payment to Google Apps Script

      const gasUrl = process.env.GAS_WEB_APP_URL;
      const bridgeToken = process.env.CF_BRIDGE_TOKEN;

      if (!gasUrl || !bridgeToken) {
        throw new Error(
          'Apps Script URL or bridge token is missing.'
        );
      }

      console.log(
        '[APPS SCRIPT] Forwarding verified payment.'
      );

      const forwardResponse = await fetch(gasUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          bridgeToken,
          student
        }),
        redirect: 'follow'
      });

      const responseText = await forwardResponse.text();

      let result;

      try {
        result = JSON.parse(responseText);
      } catch (error) {
        console.error(
          '[APPS SCRIPT ERROR] Invalid JSON response.'
        );

        throw new Error(
          'Apps Script returned an invalid response.'
        );
      }

      console.log('[APPS SCRIPT RESULT]', {
        httpStatus: forwardResponse.status,
        success: result.success,
        duplicate: result.duplicate || false,
        message: result.message || ''
      });

      if (
        !forwardResponse.ok ||
        result.success !== true
      ) {
        throw new Error(
          result.message ||
          'Google Sheets save failed.'
        );
      }

      // L. Return success to Cashfree

      if (result.duplicate) {
        console.log(
          '[COMPLETED] Duplicate order ignored:',
          student.orderId
        );
      } else {
        console.log(
          '[COMPLETED] Student payment saved:',
          student.orderId
        );
      }

      return res.status(200).send(
        'Payment processed successfully.'
      );

    } catch (error) {
      console.error(
        '[WEBHOOK PROCESSING ERROR]',
        error.message
      );

      return res.status(500).send(
        'Temporary webhook processing error.'
      );
    }
  }
);

// --------------------------------------------------
// 6. START SERVER
// --------------------------------------------------

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Cashfree Student Bridge running on port ${PORT}`
  );
});
