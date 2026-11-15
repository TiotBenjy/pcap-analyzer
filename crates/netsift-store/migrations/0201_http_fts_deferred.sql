-- HTTP search indexes built once at the end of the import (finalizer `http`, P4.2). Range 0200-0299.
-- The insert triggers fed both trigram FTS5 tables row by row, and the per-transaction savepoint
-- of the writer made FTS5 flush a new segment for every transaction (then merge them): about
-- half a millisecond per transaction, the most expensive record of an import. The finalizer
-- rebuilds both tables from their content tables instead; on a session imported before this
-- migration, it runs at the first opening (ADR-014) and rewrites the same content.
DROP TRIGGER IF EXISTS http_transactions_fts_insert;
DROP TRIGGER IF EXISTS http_headers_fts_insert;
