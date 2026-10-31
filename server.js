
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
  console.log(
    `[INCOMING REQUEST] ${req.method} ${req.path}`
  );

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
  res.status(200).send(
    'Cashfree Student Bridge is running.'
  );
});

// Cashfree or a monitoring service may check the endpoint with GET.
app.get(WEBHOOK_PATH, (req, res) => {
  console.log('[HEALTH CHECK] Payment Form endpoint is reachable.');

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
// 4. HELPER FUNCTIONS
// --------------------------------------------------

function normalize(value) {
  return String(value || '')
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
      field.title ||
      field.label ||
      field.field_name ||
      field.name
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
      // ----------------------------------------------
      // A. Validate request body
      // ----------------------------------------------

      if (!Buffer.isBuffer(req.body)) {
        console.error(
          '[ERROR] Request body is not raw JSON.'
        );

        return res.status(400).send(
          'Invalid webhook request body.'
        );
      }

      const rawBody = req.body.toString('utf8');

      // ----------------------------------------------
      // B. Read Cashfree signature headers
      // ----------------------------------------------

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

      // ----------------------------------------------
      // C. Verify the Cashfree signature
      // ----------------------------------------------

      const validSignature = verifyCashfreeSignature(
        timestamp,
        rawBody,
        signature,
        secret
      );

      if (!validSignature) {
        console.error(
          '[SIGNATURE ERROR] Cashfree signature verification failed.'
        );

        return res.status(401).send(
          'Invalid Cashfree webhook signature.'
        );
      }

      console.log(
        '[SIGNATURE SUCCESS] Cashfree signature verified.'
      );

      // ----------------------------------------------
      // D. Parse verified webhook payload
      // ----------------------------------------------

      let event;

      try {
        event = JSON.parse(rawBody);
      } catch (error) {
        console.error('[ERROR] Invalid JSON webhook payload.');

        return res.status(400).send(
          'Invalid JSON payload.'
        );
      }

      const data = event.data || {};
      const form = data.form || {};
      const order = data.order || {};
      const payment = data.payment || {};

      // Log identifiers and status only.
      // Never log student names, phone numbers or emails.
      console.log('[CASHFREE EVENT DETAILS]', {
        eventType: event.type || 'Missing',
        formId: form.form_id || '',
        cashfreeFormId: form.cf_form_id || '',
        orderIdPresent: Boolean(order.order_id),
        orderStatus: order.order_status || '',
        paymentStatus: payment.payment_status || ''
      });

      // ----------------------------------------------
      // E. Check event type
      // ----------------------------------------------

      if (event.type !== EXPECTED_EVENT) {
        console.log(
          '[IGNORED] Unexpected Cashfree event:',
          event.type || 'Missing'
        );

        return res.status(200).send(
          'Event ignored.'
        );
      }

      if (!order.order_id) {
        console.error(
          '[ERROR] Cashfree Order ID is missing.'
        );

        return res.status(400).send(
          'Order information missing.'
        );
      }

      // ----------------------------------------------
      // F. Check production form ID
      // ----------------------------------------------

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

      if (allowedFormId) {
        console.log('[FORM ID CHECK]', {
          configuredFormId: allowedFormId,
          receivedFormIds: receivedFormIds
        });

        if (!receivedFormIds.includes(allowedFormId)) {
          console.warn(
            '[IGNORED] Cashfree Form ID mismatch.'
          );

          return res.status(200).send(
            'Different form ignored.'
          );
        }
      }

      // ----------------------------------------------
      // G. Check successful payment
      // ----------------------------------------------

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
        console.log('[IGNORED] Payment is not successful.', {
          orderStatus: orderStatus || 'Missing',
          paymentStatus: paymentStatus || 'Missing'
        });

        return res.status(200).send(
          'Payment not successful.'
        );
      }

      console.log(
        '[PAYMENT SUCCESS] Verified successful payment.'
      );

      // ----------------------------------------------
      // H. Extract customer details and custom fields
      // ----------------------------------------------

      const customer =
        order.customer_details ||
        data.customer_details ||
        {};

      const fields =
        customer.customer_fields ||
        order.customer_fields ||
        data.customer_fields ||
        [];

      // Log field names only, never their values.
      if (Array.isArray(fields)) {
        console.log(
          '[CUSTOM FIELD LABELS]',
          fields.map(field =>
            field.title ||
            field.label ||
            field.field_name ||
            field.name ||
            'Unknown'
          )
        );
      } else {
        console.log(
          '[CUSTOM FIELD LABELS] No custom-field array found.'
        );
      }

      const amount = Number(
        order.order_amount ??
        payment.payment_amount ??
        0
      );

      const student = {
        name: String(
          customer.customer_name || ''
        ).trim(),

        email: String(
          customer.customer_email || ''
        ).trim(),

        phone: String(
          customer.customer_phone || ''
        ).trim(),

        domain: getCustomField(
          fields,
          'Domain Name',
          'Domain'
        ),

        empCode: getCustomField(
          fields,
          'Emp Code',
          'Employee Code',
          'Employee ID'
        ),

        college: getCustomField(
          fields,
          'College Name',
          'College'
        ),

        paymentId: String(
          payment.cf_payment_id ||
          payment.payment_id ||
          order.transaction_id ||
          ''
        ),

        orderId: String(order.order_id),

        amount: amount,

        paymentStatus: 'PAID',

        paymentDate:
          event.event_time ||
          new Date().toISOString()
      };

      if (
        !student.orderId ||
        !Number.isFinite(student.amount) ||
        student.amount <= 0
      ) {
        console.error(
          '[ERROR] Invalid order ID or payment amount.'
        );

        return res.status(400).send(
          'Invalid payment details.'
        );
      }

      const missingFields = [];

      if (!student.name) missingFields.push('Name');
      if (!student.email) missingFields.push('Email');
      if (!student.phone) missingFields.push('Phone Number');
      if (!student.domain) missingFields.push('Domain Name');
      if (!student.empCode) missingFields.push('Emp Code');
      if (!student.college) missingFields.push('College Name');
      if (!student.paymentId) missingFields.push('Payment ID');

      console.log('[STUDENT FIELD CHECK]', {
        namePresent: Boolean(student.name),
        emailPresent: Boolean(student.email),
        phonePresent: Boolean(student.phone),
        domainPresent: Boolean(student.domain),
        empCodePresent: Boolean(student.empCode),
        collegePresent: Boolean(student.college),
        paymentIdPresent: Boolean(student.paymentId),
        missingFields: missingFields
      });

      // ----------------------------------------------
      // I. Forward verified details to Apps Script
      // ----------------------------------------------

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
        console.error(
          '[APPS SCRIPT ERROR] Response was not JSON.'
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
          'Apps Script could not save the student.'
        );
      }

      // ----------------------------------------------
      // J. Final response
      // ----------------------------------------------

      if (result.duplicate) {
        console.log(
          '[COMPLETED] Duplicate order was safely ignored:',
          student.orderId
        );
      } else {
        console.log(
          '[COMPLETED] New student record saved:',
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

      // Cashfree can retry delivery after a non-2xx response.
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
