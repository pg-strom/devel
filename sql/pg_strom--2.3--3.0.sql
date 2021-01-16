--
-- Handlers of gstore_fdw extension (renew at v3.0)
--
CREATE FUNCTION pgstrom.gstore_fdw_handler()
  RETURNS fdw_handler
  AS  'MODULE_PATHNAME','pgstrom_gstore_fdw_handler'
  LANGUAGE C STRICT;

CREATE FUNCTION pgstrom.gstore_fdw_validator(text[],oid)
  RETURNS void
  AS 'MODULE_PATHNAME','pgstrom_gstore_fdw_validator'
  LANGUAGE C STRICT;

CREATE FOREIGN DATA WRAPPER gstore_fdw
  HANDLER   pgstrom.gstore_fdw_handler
  VALIDATOR pgstrom.gstore_fdw_validator;

CREATE SERVER gstore_fdw
  FOREIGN DATA WRAPPER gstore_fdw;

CREATE OR REPLACE FUNCTION pgstrom.gstore_fdw_post_creation()
  RETURNS event_trigger
  AS 'MODULE_PATHNAME','pgstrom_gstore_fdw_post_creation'
  LANGUAGE C STRICT;
CREATE EVENT TRIGGER pgstrom_gstore_fdw_post_creation
  ON ddl_command_end
WHEN tag IN ('CREATE FOREIGN TABLE')
EXECUTE PROCEDURE pgstrom.gstore_fdw_post_creation();

CREATE FUNCTION public.gstore_fdw_apply_redo(regclass)
  RETURNS int
  AS 'MODULE_PATHNAME','pgstrom_gstore_fdw_apply_redo'
  LANGUAGE C STRICT;

CREATE FUNCTION public.gstore_fdw_compaction(regclass, bool = false)
  RETURNS int
  AS 'MODULE_PATHNAME','pgstrom_gstore_fdw_compaction'
  LANGUAGE C STRICT;

SELECT pgstrom.define_shell_type('gstore_fdw_sysattr',6116,'pgstrom');
CREATE FUNCTION pgstrom.gstore_fdw_sysattr_in(cstring)
  RETURNS pgstrom.gstore_fdw_sysattr
  AS 'MODULE_PATHNAME','pgstrom_gstore_fdw_sysattr_in'
  LANGUAGE C STRICT IMMUTABLE;
CREATE FUNCTION pgstrom.gstore_fdw_sysattr_out(pgstrom.gstore_fdw_sysattr)
  RETURNS cstring
  AS 'MODULE_PATHNAME','pgstrom_gstore_fdw_sysattr_out'
  LANGUAGE C STRICT IMMUTABLE;
CREATE TYPE pgstrom.gstore_fdw_sysattr
(
  INPUT = pgstrom.gstore_fdw_sysattr_in,
  OUTPUT = pgstrom.gstore_fdw_sysattr_out,
  INTERNALLENGTH = 12,
  ALIGNMENT = int4
);

---
--- GPU memory store
---

--- gpustore_synchronizer(max_num_rows, gpu_device_id)
CREATE FUNCTION pgstrom.gpustore_synchronizer(bigint,int=-1)
  RETURNS trigger
  AS 'MODULE_PATHNAME','pgstrom_gpustore_synchronizer'
  LANGUAGE C;

---
--- Deprecated functions
---
DROP FUNCTION IF EXISTS public.gpu_device_name(int);
DROP FUNCTION IF EXISTS public.gpu_global_memsize(int);
DROP FUNCTION IF EXISTS public.gpu_max_blocksize(int);
DROP FUNCTION IF EXISTS public.gpu_warp_size(int);
DROP FUNCTION IF EXISTS public.gpu_max_shared_memory_perblock(int);
DROP FUNCTION IF EXISTS public.gpu_num_registers_perblock(int);
DROP FUNCTION IF EXISTS public.gpu_num_multiptocessors(int);
DROP FUNCTION IF EXISTS public.gpu_num_cuda_cores(int);
DROP FUNCTION IF EXISTS public.gpu_cc_major(int);
DROP FUNCTION IF EXISTS public.gpu_cc_minor(int);
DROP FUNCTION IF EXISTS public.gpu_pci_id(int);

DROP TYPE IF EXISTS pgstrom.__pgstrom_device_preserved_meminfo CASCADE;
