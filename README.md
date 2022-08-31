# SpamAssassin plugin that checks if an email message respects its domain DMARC policy.

The plugin can save DMARC reports in a database, reports can be sent later to external
mail servers.
The main branch is developed on Apache SpamAssassin 4.x src tree and it will be kept in sync here,
the version compatible with Apache SpamAssassin 3.4.x is on the "3.4" branch.
See Mail::DMARC::Report for additional documentation about how to configure reporting.
