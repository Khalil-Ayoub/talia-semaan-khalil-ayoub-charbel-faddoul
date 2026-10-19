# Integrated project verification

All nine services were merged into main through student pull requests 1, 3 and 4 on 19 October 2026. Their original commits and branches are preserved.

The final merged source passed all 40 tests using Python 3.11:

```
python -m unittest discover -s tests -p "test_*.py" -v
```

The suite includes 39 isolated tests and one integration test that runs all nine real applications over HTTP against a temporary SQLite database. The final merged run completed in 28.720 seconds with result OK. Isolated tests use explicit dependency doubles; the full-system test does not substitute another student's service.

The common report embeds actual Postman and database evidence captured on 18 October 2026: 131 requests passed their expected HTTP status assertions, with no failed assertions or runner errors. Expected permission and validation errors are successful negative tests. Four actual GitHub screenshots captured in signed-in Chrome on 19 October 2026 show main history and each student's merged service pull request. All 151 raw screenshots are in screenshots/. Their hashes, GitHub capture URLs, structured GitHub records and the final test log are in docs/evidence/.

The three personal Postman collections are in postman/. Their runtime variables must be set for a fresh local database; real passwords, reusable tokens and service secrets are excluded.
