# Data processing terms (draft)

**A draft for a lawyer to review before it is signed with anyone. It is not
legal advice.** It is written to match what the software does today; `/security`
on any deployment says the same in plain words.

## 1. Who is who

- **The customer** decides why and how its security alerts are processed. Under
  India's Digital Personal Data Protection Act, 2023 it is the data fiduciary
  for any personal data in those alerts.
- **Triagle** processes the alerts on the customer's instructions, as a data
  processor. Where a managed security provider stands between the two, the
  provider is the customer's processor and Triagle is the provider's.

## 2. What is processed, and why

- **What:** security alerts from the tools the customer connects. An alert can
  hold machine names, account names, network addresses and command lines. It
  can hold personal data, such as a user name or an email address.
- **Why:** to decide which alerts need a person, to write the reports around
  them, and to record what the customer's analysts decided. For nothing else.
- **Not processed:** raw logs, files, mailboxes or passwords.

## 3. Instructions

Triagle processes the alerts only as these terms and the customer's written
instructions say. It does not sell them, share them, or use them to train a
model.

## 4. Where, and who else

- **Where:** in the cloud region named in the order form. For a customer in
  India, a region in India.
- **Sub-processor:** Google Cloud (hosting, storage, and the Gemini model that
  writes reports). Triagle tells the customer before adding another, and the
  customer may object.
- **The model:** text sent to the model has Aadhaar numbers, PANs, UPI IDs,
  phone numbers and email addresses replaced by placeholders first.

## 5. Security

Triagle keeps the measures described at `/security`: encryption in transit and
at rest, sign-in with roles and a second factor or single sign-on, a separate
key for each customer, an audit log, and no response action without a named
analyst. It tells the customer before weakening any of them.

## 6. People

Only people who need the alerts to run the service can reach them, and each
is bound to keep them confidential.

## 7. If something goes wrong

Triagle tells the customer without delay, and within 6 hours of becoming
aware, of any breach that affects the customer's alerts: what happened, what
is affected, and what has been done. That leaves the customer able to meet its
own duties to CERT-In and to the Data Protection Board.

## 8. Keeping and deleting

- Triagle holds a working queue of recent alerts, not an archive. The
  customer's own tools remain the record.
- On written request, and at the end of the agreement, Triagle deletes the
  customer's alerts and decisions within 30 days and confirms it in writing.
  Backups expire within the period stated in the order form.

## 9. Helping the customer

Triagle helps the customer answer a request from a person about their own
data, and gives the customer the information it needs to show it meets the
law, including a yearly summary of security testing.

## 10. Checking

Once a year, on 30 days' notice, the customer may review Triagle's security
measures, by questionnaire or by an agreed independent report.

## Still to fill in before signing

- The names of the parties and the order form (region, retention, fees).
- Liability, governing law and the place of disputes.
- Whether the customer is a "significant data fiduciary", which adds duties.
