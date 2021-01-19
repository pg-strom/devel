/*
 * mysql_client.c - MySQL specific portion for mysql2arrow command
 *
 * Copyright 2020 (C) KaiGai Kohei <kaigai@heterodb.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the PostgreSQL License. See the LICENSE file.
 */
#include <mysql.h>
#include "sql2arrow.h"
#include <limits.h>

/* static variables */
static char	   *mysql_timezone = NULL;
static int		__exp10[] = {1,
							 10,
							 100,
							 1000,
							 10000,
							 100000,
							 1000000,
							 10000000,
							 100000000,
							 1000000000 };

/*
 * put values handlers
 */
static inline void
__put_inline_null_value(SQLfield *column, size_t row_index, int sz)
{
	column->nullcount++;
	sql_buffer_clrbit(&column->nullmap, row_index);
	sql_buffer_append_zero(&column->values, sz);
}

static inline size_t
__buffer_usage_inline_type(SQLfield *column)
{
	size_t		usage;

	usage = ARROWALIGN(column->values.usage);
	if (column->nullcount > 0)
		usage += ARROWALIGN(column->nullmap.usage);
	return usage;
}

static inline size_t
__buffer_usage_variable_type(SQLfield *column)
{
	size_t		usage;

	usage = (ARROWALIGN(column->values.usage) +
			 ARROWALIGN(column->extra.usage));
	if (column->nullcount > 0)
		usage += ARROWALIGN(column->nullmap.usage);
	return usage;
}

static size_t
__put_int8_value(SQLfield *column, const char *addr, int sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(uint16));
	else
	{
		int		value = atoi(addr);

		if (column->arrow_type.Int.is_signed
			? (value < SCHAR_MIN || value > SCHAR_MAX)
			: (value < 0 || value > UCHAR_MAX))
			Elog("value '%s' is out of range for %s",
				 addr, column->arrow_typename);
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, sizeof(uint8));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
__put_int16_value(SQLfield *column, const char *addr, int sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(uint16));
	else
	{
		int		value = atoi(addr);

		if (column->arrow_type.Int.is_signed
			? (value < SHRT_MIN || value > SHRT_MAX)
			: (value < 0 || value > USHRT_MAX))
			Elog("value '%s' is out of range for %s",
				 addr, column->arrow_typename);
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, sizeof(uint16));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
__put_int32_value(SQLfield *column, const char *addr, int sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(uint32));
	else
	{
		long	value = atol(addr);

		if (column->arrow_type.Int.is_signed
			? (value < INT_MIN || value > INT_MAX)
			: (value < 0 || value > UINT_MAX))
			Elog("value '%s' is out of range for %s",
				 addr, column->arrow_typename);
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, sizeof(uint32));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
__put_int64_value(SQLfield *column, const char *addr, int sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(uint64));
	else if (column->arrow_type.Int.is_signed)
	{
		int64	value = strtol(addr, NULL, 10);

		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, sizeof(uint64));
	}
	else
	{
		uint64	value = strtoul(addr, NULL, 10);

		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, sizeof(uint64));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
put_int_value(SQLfield *column, const char *addr, int sz)
{
	switch (column->arrow_type.Int.bitWidth)
	{
		case 8:
			column->put_value = __put_int8_value;
			break;
		case 16:
			column->put_value = __put_int16_value;
			break;
		case 32:
			column->put_value = __put_int32_value;
			break;
		case 64:
			column->put_value = __put_int64_value;
			break;
		default:
			Elog("unexpected Arrow::Int.bitWidth (%d)",
				 column->arrow_type.Int.bitWidth);
	}
	return column->put_value(column, addr, sz);
}

static size_t
__put_float32_value(SQLfield *column, const char *addr, int sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(float));
	else
	{
		float	value = atof(addr);

		sql_buffer_setbit(&column->nullmap, row_index);
        sql_buffer_append(&column->values, &value, sizeof(float));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
__put_float64_value(SQLfield *column, const char *addr, int sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(double));
	else
	{
		double	value = atof(addr);

		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, sizeof(double));
	}
	return __buffer_usage_inline_type(column);
}

static size_t
put_float_value(SQLfield *column, const char *addr, int sz)
{
	switch (column->arrow_type.FloatingPoint.precision)
	{
		case ArrowPrecision__Single:
			column->put_value = __put_float32_value;
			break;
		case ArrowPrecision__Double:
			column->put_value = __put_float64_value;
			break;
		default:
            Elog("unexpected Arrow::FloatingPoint.precision (%d)",
				 column->arrow_type.FloatingPoint.precision);
	}
    return column->put_value(column, addr, sz);
}

static size_t
put_decimal_value(SQLfield *column, const char *addr, int sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(int128));
	else
	{
		char   *pos = (char *)addr;
		char   *end;
		int		dscale = column->arrow_type.Decimal.scale;
		bool	negative = false;
		int128	value;

		if (*pos == '-')
		{
			negative = true;
			pos++;
		}
		else if (*pos == '+')
			pos++;

		end = strchr(pos, '.');
		if (!end)
			end = pos + strlen(pos);
		if (end - pos < 20)
		{
			char   *point;

			value = strtoul(pos, &point, 10);
			if (*point != '.' && *point != '\0')
				Elog("invalid Decimal value [%s]", addr);			
		}
		else
		{
			if (dscale < 0)
				end += dscale;
			value = 0;
			while (pos < end)
				value = 10 * value + (*pos++ - '0');
		}

		if (dscale > 0 && *end != '\0')
		{
			assert(*end == '.');
			for (pos = end + 1; dscale > 0; dscale--)
			{
				if (!isdigit(*pos))
					value = 10 * value;
				else
					value = 10 * value + (*pos++ - '0');
			}
		}
		if (negative)
			value = -value;		
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, sizeof(int128));
	}
	return __buffer_usage_inline_type(column);
}

static long
date2j(int y, int m, int d)
{
	long	julian;
	long	century;

	if (m > 2)
	{
		m += 1;
		y += 4800;
	}
	else
	{
		m += 13;
		y += 4799;
	}
	century = y / 100;
	julian = y * 365 - 32167;
	julian += y / 4 - century + century / 4;
	julian += 7834 * m / 256 + d;

	return julian;
}
#define UNIX_EPOCH_JDATE	2440588 /* == date2j(1970, 1, 1) */

/*
 * Date
 */
static inline size_t
__put_date_value_generic(SQLfield *column, const char *addr, int length,
						 int adjustment, int arrow_sz)
{
	size_t		row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, arrow_sz);
	else
	{
		int		y, m, d;
		int64	value;

		if (sscanf(addr, "%d-%d-%d", &y, &m, &d) != 3)
			Elog("invalid Date value: [%s]", addr);
		value = date2j(y, m, d) - UNIX_EPOCH_JDATE;
		if (adjustment > 0)
			value *= adjustment;
		else if (adjustment < 0)
			value /= adjustment;
		sql_buffer_append(&column->values, &value, arrow_sz);
	}
	return __buffer_usage_inline_type(column);		
}

static size_t
put_date_day_value(SQLfield *column, const char *addr, int sz)
{
	return __put_date_value_generic(column, addr, sz, 0, sizeof(int32));
}

static size_t
put_date_ms_value(SQLfield *column, const char *addr, int sz)
{
	return __put_date_value_generic(column, addr, sz, 1000000, sizeof(int64));
}

static size_t
put_date_value(SQLfield *column, const char *addr, int sz)
{
	switch (column->arrow_type.Date.unit)
	{
		case ArrowDateUnit__Day:
			column->put_value = put_date_day_value;
			break;
		case ArrowDateUnit__MilliSecond:
			column->put_value = put_date_ms_value;
			break;
		default:
			Elog("Unknown unit of Arrow::Date type (%d)",
				 column->arrow_type.Date.unit);
	}
	return column->put_value(column, addr, sz);
}

/*
 * Time
 */
static inline size_t
__put_time_value_generic(SQLfield *column, const char *addr, int sz,
						 int arrow_scale, int arrow_sz)
{
	size_t	row_index = column->nitems++;
	if (!addr)
		__put_inline_null_value(column, row_index, arrow_sz);
	else
	{
		int		h, m, s, frac = 0;
		int64	value;
		char   *pos = strchr(addr, '.');

		if (pos)
		{
			int		scale = strlen(pos + 1);

			if (scale < 0 || scale > 6)
				Elog("invalid Time value [%s]", addr);
			scale -= arrow_scale;
			if (sscanf(addr, "%d:%d:%d.%d", &h, &m, &s, &frac) != 4)
				Elog("invalid Time value [%s]", addr);
			if (scale < 0)
				frac *= __exp10[-scale];
			else if (scale > 0)
				frac /= __exp10[scale];
		}
		else
		{
			if (sscanf(addr, "%d:%d:%d", &h, &m, &s) != 3)
				Elog("invalid Time value [%s]", addr);
		}
		value = 3600L * (long)h + 60L * (long)m + (long)s;
		value = value * __exp10[arrow_scale] + frac;

		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, arrow_sz);
	}
	return __buffer_usage_inline_type(column);
}

static size_t
__put_time_sec_value(SQLfield *column, const char *addr, int sz)
{
	return __put_time_value_generic(column, addr, sz, 0, sizeof(int32));
}

static size_t
__put_time_ms_value(SQLfield *column, const char *addr, int sz)
{
	return __put_time_value_generic(column, addr, sz, 3, sizeof(int32));
}

static size_t
__put_time_us_value(SQLfield *column, const char *addr, int sz)
{
	return __put_time_value_generic(column, addr, sz, 6, sizeof(int64));
}

static size_t
__put_time_ns_value(SQLfield *column, const char *addr, int sz)
{
	return __put_time_value_generic(column, addr, sz, 9, sizeof(int64));
}

static size_t
put_time_value(SQLfield *column, const char *addr, int sz)
{
	switch (column->arrow_type.Time.unit)
	{
		case ArrowTimeUnit__Second:
			column->put_value = __put_time_sec_value;
			break;
		case ArrowTimeUnit__MilliSecond:
			column->put_value = __put_time_ms_value;
			break;
		case ArrowTimeUnit__MicroSecond:
			column->put_value = __put_time_us_value;
			break;
		case ArrowTimeUnit__NanoSecond:
			column->put_value = __put_time_ns_value;
			break;
		default:
			Elog("unknown ArrowTimeUnit: %d",
				 (int)column->arrow_type.Time.unit);
	}
	return column->put_value(column, addr, sz);
}

/*
 * Timestamp
 */
static inline size_t
__put_timestamp_value_generic(SQLfield *column, const char *addr, int sz,
							  int arrow_scale, int arrow_sz)
{
	size_t	row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, arrow_sz);
	else
	{
		int		year, mon, day, hour, min, sec, frac = 0;
		int64	value;
		char   *pos = strchr(addr, '.');

		if (pos != NULL)
		{
			int		scale = strlen(pos + 1);

			scale -= arrow_scale;
			if (sscanf(addr, "%04d-%02d-%02d %d:%d:%d.%d",
					   &year, &mon, &day,
					   &hour, &min, &sec, &frac) != 7)
				Elog("invalid Time value [%s]", addr);
			if (scale < 0)
				frac *= __exp10[-scale];
			else if (scale > 0)
				frac /= __exp10[scale];
		}
		else
		{
			if (sscanf(addr, "%04d-%02d-%02d %d:%d:%d",
					   &year, &mon, &day,
					   &hour, &min, &sec) != 6)
				Elog("invalid Timestamp value [%s]", addr);
		}
		value = date2j(year, mon, day) - UNIX_EPOCH_JDATE;
		value = 86400L * value + (3600L * hour + 60L * min + sec);
		value = value * __exp10[arrow_scale] + frac;

		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &value, arrow_sz);
	}
	return __buffer_usage_inline_type(column);
}

static size_t
__put_timestamp_sec_value(SQLfield *column, const char *addr, int sz)
{
	return __put_timestamp_value_generic(column, addr, sz, 0, sizeof(int64));
}

static size_t
__put_timestamp_ms_value(SQLfield *column, const char *addr, int sz)
{
	return __put_timestamp_value_generic(column, addr, sz, 3, sizeof(int64));
}

static size_t
__put_timestamp_us_value(SQLfield *column, const char *addr, int sz)
{
	return __put_timestamp_value_generic(column, addr, sz, 6, sizeof(int64));
}

static size_t
__put_timestamp_ns_value(SQLfield *column, const char *addr, int sz)
{
	return __put_timestamp_value_generic(column, addr, sz, 9, sizeof(int64));
}

static size_t
put_timestamp_value(SQLfield *column, const char *addr, int sz)
{
	switch (column->arrow_type.Timestamp.unit)
	{
		case ArrowTimeUnit__Second:
			column->put_value = __put_timestamp_sec_value;
			break;
		case ArrowTimeUnit__MilliSecond:
			column->put_value = __put_timestamp_ms_value;
			break;
		case ArrowTimeUnit__MicroSecond:
			column->put_value = __put_timestamp_us_value;
			break;
		case ArrowTimeUnit__NanoSecond:
			column->put_value = __put_timestamp_ns_value;
			break;
		default:
			Elog("unknown ArrowTimeUnit: %d",
				 (int)column->arrow_type.Timestamp.unit);
	}
	return column->put_value(column, addr, sz);
}

static size_t
put_variable_value(SQLfield *column, const char *addr, int sz)
{
	size_t		row_index = column->nitems++;

	if (row_index == 0)
		sql_buffer_append_zero(&column->values, sizeof(uint32));
	if (!addr)
	{
		column->nullcount++;
		sql_buffer_clrbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values,
						  &column->extra.usage, sizeof(uint32));
	}
	else
	{
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->extra, addr, sz);
		sql_buffer_append(&column->values,
						  &column->extra.usage, sizeof(uint32));
	}
	return __buffer_usage_variable_type(column);
}

#if 0
/*
 * NOTE: Right now, we have no way to fetch column's attribute during
 * query execution (for more correctness, libmysqlclient does not allow
 * to run another query before mysql_free_result(), so we cannot run
 *   SHOW COLUMNS FROM <tablename> LIKE '<columnname>'
 * according to the query results.
 * So, mysql2arrow saves Enum data type in MySQL as normal Utf8/Binary
 * values, without creation of DictionaryBatch chunks.
 */
static size_t
put_dictionary_value(SQLfield *column, const char *addr, int sz)
{
	SQLdictionary *enumdict = column->enumdict;
	hashItem   *hitem;
	uint32		hash, hindex;
	size_t		row_index = column->nitems++;

	if (!addr)
		__put_inline_null_value(column, row_index, sizeof(uint32));
	else
	{
		hash = hash_any((unsigned char *)addr, sz);
		hindex = hash % enumdict->nslots;
		for (hitem = enumdict->hslots[hindex];
			 hitem != NULL;
			 hitem = hitem->next)
		{
			if (hitem->hash == hash &&
				hitem->label_sz == sz &&
				memcmp(hitem->label, addr, sz) == 0)
				break;
		}
		if (!hitem)
			Elog("Enum label was not found");
		sql_buffer_setbit(&column->nullmap, row_index);
		sql_buffer_append(&column->values, &hitem->index, sizeof(uint32));
	}
	return __buffer_usage_variable_type(column);
}
#endif

/*
 * mysql_setup_attribute
 */
static int
mysql_setup_attribute(MYSQL *conn,
					  MYSQL_FIELD *my_field,
					  ArrowField *arrow_field,
					  SQLtable *table,
					  SQLfield *column,
					  int attnum)
{
	ArrowType  *arrow_type = (arrow_field ? &arrow_field->type : NULL);
	bool		is_signed = ((my_field->flags & UNSIGNED_FLAG) == 0);
	bool		is_binary = ((my_field->flags & BINARY_FLAG) != 0);
//	bool		is_enum   = ((my_field->flags & ENUM_FLAG) != 0);
	int			bitWidth = -1;
	int			precision = -1;
	int			dscale;
	int			unit;
	char		temp[120];
	const char *tz_name = NULL;
	
	memset(column, 0, sizeof(SQLfield));
	column->field_name = pstrdup(my_field->name);
	column->sql_type.mysql.typeid = (int)my_field->type;
	switch (my_field->type)
	{
		/*
		 * ArrowTypeInt
		 */
		case MYSQL_TYPE_TINY:
			if (bitWidth < 0)
				bitWidth = 8;
		case MYSQL_TYPE_SHORT:
		case MYSQL_TYPE_YEAR:
			if (bitWidth < 0)
				bitWidth = 16;
		case MYSQL_TYPE_INT24:
		case MYSQL_TYPE_LONG:
			if (bitWidth < 0)
				bitWidth = 32;
		case MYSQL_TYPE_LONGLONG:
			if (bitWidth < 0)
				bitWidth = 64;
			if (arrow_type)
			{
				if (arrow_type->node.tag != ArrowNodeTag__Int ||
					arrow_type->Int.bitWidth < bitWidth)
					Elog("attribute %d is not compatible to %s",
						 attnum, arrow_type->node.tagName);
				if (arrow_type->Int.bitWidth > bitWidth)
					bitWidth = arrow_type->Int.bitWidth;
				is_signed = arrow_type->Int.is_signed;
			}
			snprintf(temp, sizeof(temp), "%s%d",
					 is_signed ? "Int" : "Uint", bitWidth);

			initArrowNode(&column->arrow_type, Int);
			column->arrow_type.Int.is_signed = is_signed;
			column->arrow_type.Int.bitWidth = bitWidth;
			column->arrow_typename = pstrdup(temp);
			column->put_value = put_int_value;
			return 2;		/* nullmap + values */
		/*
		 * ArrowTypeFloatingPoint
		 */
		case MYSQL_TYPE_FLOAT:
			if (precision < 0)
				precision = ArrowPrecision__Single;
		case MYSQL_TYPE_DOUBLE:
			if (precision < 0)
				precision = ArrowPrecision__Double;
			if (arrow_type)
			{
				if (arrow_type->node.tag != ArrowNodeTag__FloatingPoint ||
					arrow_type->FloatingPoint.precision < precision)
					Elog("attribute %d is not compatible to %s",
						 attnum, arrow_type->node.tagName);
				precision = arrow_type->FloatingPoint.precision;
			}
			initArrowNode(&column->arrow_type, FloatingPoint);
			column->arrow_type.FloatingPoint.precision = precision;
			switch (precision)
			{
				case ArrowPrecision__Half:
					column->arrow_typename = "Float16";
					break;
				case ArrowPrecision__Single:
					column->arrow_typename = "Float32";
					break;
				case ArrowPrecision__Double:
					column->arrow_typename = "Float64";
					break;
				default:
					Elog("unexpected FloatingPoint precision (%d)", precision);
			}
			column->put_value = put_float_value;
			return 2;		/* nullmap + values */
		/*
		 * ArrowTypeDecimal
		 */
		case MYSQL_TYPE_DECIMAL:
		case MYSQL_TYPE_NEWDECIMAL:
			printf("Decimal length=%lu max_length=%lu decimals=%d\n",
				   my_field->length, my_field->max_length, my_field->decimals);
			precision = my_field->max_length;
			dscale = my_field->decimals;
			if (arrow_type)
			{
				if (arrow_type->node.tag != ArrowNodeTag__Decimal)
					Elog("attribute %d is not compatible to %s",
						 attnum, arrow_type->node.tagName);
				precision = arrow_type->Decimal.precision;
				dscale = arrow_type->Decimal.scale;
			}
			initArrowNode(&column->arrow_type, Decimal);
			column->arrow_type.Decimal.precision = precision;
			column->arrow_type.Decimal.scale = dscale;
			column->arrow_typename  = "Decimal";
			column->put_value       = put_decimal_value;
			return 2;		/* nullmap + values */
		/*
		 * ArrowTypeDate
		 */
		case MYSQL_TYPE_DATE:
			unit = ArrowDateUnit__Day;
			if (arrow_type)
			{
				if (arrow_type->node.tag != ArrowNodeTag__Date)
					Elog("attribute %d is not compatible to %s",
						 attnum, arrow_type->node.tagName);
				unit = arrow_type->Date.unit;
				if (unit != ArrowDateUnit__Day &&
					unit != ArrowDateUnit__MilliSecond)
					Elog("unknown unit (%d) for Arrow::Date", unit);
			}
			initArrowNode(&column->arrow_type, Date);
			column->arrow_type.Date.unit = unit;
			column->arrow_typename  = "Date";
			column->put_value       = put_date_value;
			return 2;		/* nullmap + values */
		/*
		 * ArrowTypeTime
		 */
		case MYSQL_TYPE_TIME:
			if (my_field->decimals == 0)
				unit = ArrowTimeUnit__Second;
			else if (my_field->decimals <= 3)
				unit = ArrowTimeUnit__MilliSecond;
			else if (my_field->decimals <= 6)
				unit = ArrowTimeUnit__MicroSecond;
			else
				unit = ArrowTimeUnit__NanoSecond;
			if (arrow_type)
			{
				if (arrow_type->node.tag != ArrowNodeTag__Time)
					Elog("attribute %d is not compatible to %s",
						 attnum, arrow_type->node.tagName);
				unit = arrow_type->Time.unit;
				if (unit == ArrowTimeUnit__Second ||
					unit == ArrowTimeUnit__MilliSecond)
				{
					if (arrow_type->Time.bitWidth != 32)
						Elog("Arrow::Time has wrong bitWidth (%d)",
							 arrow_type->Time.bitWidth);
				}
				else if (unit == ArrowTimeUnit__MicroSecond ||
						 unit == ArrowTimeUnit__NanoSecond)
				{
					if (arrow_type->Time.bitWidth != 64)
						Elog("Arrow::Time has wrong bitWidth (%d)",
							 arrow_type->Time.bitWidth);
				}
				else
					Elog("unknown unit (%d) for Arrow::Time", unit);
			}
			if (unit == ArrowTimeUnit__Second ||
				unit == ArrowTimeUnit__MilliSecond)
				bitWidth = 32;
			else if (unit == ArrowTimeUnit__MicroSecond ||
					 unit == ArrowTimeUnit__NanoSecond)
				bitWidth = 64;
			else
				Elog("unknown unit (%d) for Arrow::Time", unit);
			
			initArrowNode(&column->arrow_type, Time);
			column->arrow_type.Time.unit = unit;
			column->arrow_type.Time.bitWidth = bitWidth;
			column->arrow_typename  = "Time";
			column->put_value = put_time_value;
			return 2;		/* nullmap + values */

		/*
		 * ArrowTypeTimestamp
		 */
		case MYSQL_TYPE_TIMESTAMP:
			tz_name = mysql_timezone;
		case MYSQL_TYPE_DATETIME:
			if (my_field->decimals == 0)
				unit = ArrowTimeUnit__Second;
			else if (my_field->decimals <= 3)
				unit = ArrowTimeUnit__MilliSecond;
			else if (my_field->decimals <= 6)
				unit = ArrowTimeUnit__MicroSecond;
			else
				unit = ArrowTimeUnit__NanoSecond;
			if (arrow_type)
			{
				if (arrow_type->node.tag != ArrowNodeTag__Timestamp)
					Elog("attribute %d is not compatible to %s",
						 attnum, arrow_type->node.tagName);
                unit = arrow_type->Timestamp.unit;
                if (unit != ArrowTimeUnit__Second &&
                    unit != ArrowTimeUnit__MilliSecond &&
					unit != ArrowTimeUnit__MicroSecond &&
					unit == ArrowTimeUnit__NanoSecond)
					Elog("unknown unit (%d) for Arrow::Timestamp", unit);
			}
			initArrowNode(&column->arrow_type, Timestamp);
			column->arrow_type.Timestamp.unit = unit;
			if (tz_name)
			{
				column->arrow_type.Timestamp.timezone = pstrdup(tz_name);
				column->arrow_type.Timestamp._timezone_len = strlen(tz_name);
			}
			column->arrow_typename  = "Timestamp";
			column->put_value       = put_timestamp_value;
			return 2;		/* nullmap + values */

		case MYSQL_TYPE_STRING:
		case MYSQL_TYPE_VAR_STRING:
		case MYSQL_TYPE_VARCHAR:
		case MYSQL_TYPE_BLOB:
		case MYSQL_TYPE_TINY_BLOB:
		case MYSQL_TYPE_MEDIUM_BLOB:
		case MYSQL_TYPE_LONG_BLOB:
			if (!is_binary)
			{
				/*
				 * ArrowTypeUtf8
				 */
				initArrowNode(&column->arrow_type, Utf8);
				column->arrow_typename  = "Utf8";
				column->put_value       = put_variable_value;
			}
			else
			{
				/*
				 * ArrowTypeBinary
				 */
				initArrowNode(&column->arrow_type, Binary);
				column->arrow_typename  = "Binary";
				column->put_value       = put_variable_value;
			}
			return 3;	/* nullmap + index + extra */

		case MYSQL_TYPE_NULL:
			Elog("MySQL Null data type is not supported");
		case MYSQL_TYPE_ENUM:
			Elog("MySQL Enum data type is not supported");
		case MYSQL_TYPE_SET:
			Elog("MySQL SET data type is not supported");
		case MYSQL_TYPE_BIT:
			Elog("MySQL Bit data type is not supported");
#if MYSQL_VERSION_ID >= 50700
		case MYSQL_TYPE_JSON:
			Elog("MySQL JSON data type is not supported");
#endif /* >= MySQL 5.7.00 */
		case MYSQL_TYPE_GEOMETRY:
			Elog("MySQL Geometry data type is not supported");
		default:
			Elog("unsupported MySQL data type: %d", (int)my_field->type);
	}
	return -1;
}

/*
 * callbacks from sql2arrow main logic
 */
typedef struct {
	MYSQL	   *conn;
	MYSQL_RES  *res;
} MYSTATE;

/*
 * sqldb_server_connect
 */
void *
sqldb_server_connect(const char *sqldb_hostname,
					 const char *sqldb_port_num,
					 const char *sqldb_username,
					 const char *sqldb_password,
					 const char *sqldb_database,
					 userConfigOption *sqldb_session_configs)
{
	MYSTATE	   *mystate = palloc0(sizeof(MYSTATE));
	MYSQL	   *conn;
	MYSQL_RES  *res;
	MYSQL_ROW	row;
	int			port_num = 0;
	userConfigOption *conf;
	const char *query;

	conn = mysql_init(NULL);
	if (!conn)
		Elog("failed on mysql_init");

	if (sqldb_port_num)
		port_num = atoi(sqldb_port_num);
	if (!mysql_real_connect(conn,
							sqldb_hostname,
							sqldb_username,
							sqldb_password,
							sqldb_database,
							port_num,
							NULL, 0))
		Elog("failed on mysql_real_connect: %s", mysql_error(conn));

	/*
	 * Preset user's config options
	 */
	for (conf = sqldb_session_configs; conf != NULL; conf = conf->next)
	{
		if (mysql_query(conn, conf->query) != 0)
			Elog("failed on mysql_query('%s'): %s",
				 conf->query, mysql_error(conn));
	}

	/*
     * ensure client encoding is UTF-8
     */
	query = "SET character_set_results = 'utf8'";
	if (mysql_query(conn, query) != 0)
		Elog("failed on mysql_query('%s'): %s",
			 query, mysql_error(conn));

	/*
	 * check the current timezone setting, and temporary change
	 * the configuration to UTC for Apache Arrow's binary representation
	 */
	query = "SELECT @@time_zone, @@system_time_zone";
	if (mysql_query(conn, query) != 0)
		Elog("failed on mysql_query('%s'): %s",
			 query, mysql_error(conn));
	res = mysql_store_result(conn);
	if (!res)
		Elog("failed on mysql_store_result: %s", mysql_error(conn));
	if (mysql_num_fields(res) != 2 ||
		mysql_num_rows(res) != 1)
		Elog("unexpected query result for '%s'", query);
	row = mysql_fetch_row(res);
	if (strcmp(row[0], "SYSTEM") == 0)
		mysql_timezone = pstrdup(row[1]);
	else
		mysql_timezone = pstrdup(row[0]);
	mysql_free_result(res);

	query = "SET time_zone = 'UTC'";
	if (mysql_query(conn, query) != 0)
	{
		Elog("unable to set time_zone to 'UTC': %s\n"
			 "\n"
			 "HINT: try this script below.\n"
			 "  $ mysql_tzinfo_to_sql /usr/share/zoneinfo | mysql -u root DBNAME\n",
			 mysql_error(conn));
	}
	mystate->conn = conn;
	return mystate;
}

/*
 * sqldb_begin_query
 */
SQLtable *
sqldb_begin_query(void *sqldb_state,
				  const char *sqldb_command,
				  ArrowFileInfo *af_info,
				  SQLdictionary *sql_dict_list)
{
	MYSTATE	   *mystate = (MYSTATE *)sqldb_state;
	MYSQL	   *conn = mystate->conn;
	MYSQL_RES  *res;
	SQLtable   *table;
	int			j, nfields;
	const char *query;

	/* start transaction with read-only mode */
	query = "START TRANSACTION READ ONLY";
	if (mysql_query(conn, query) != 0)
		Elog("failed on mysql_query('%s'): %s",
			 query, mysql_error(conn));

	/* exec SQL command  */
	if (mysql_query(conn, sqldb_command) != 0)
		Elog("failed on mysql_query('%s'): %s",
			 sqldb_command, mysql_error(conn));
	res = mysql_use_result(conn);
	if (!res)
		Elog("failed on mysql_use_result: %s",
			 mysql_error(conn));
	mystate->res = res;

	nfields = mysql_num_fields(res);
	if (af_info &&
		af_info->footer.schema._num_fields != nfields)
		Elog("--append is given, but number of columns are different.");
	
	/* create SQLtable buffer */
	table = palloc0(offsetof(SQLtable, columns[nfields]));
	table->nfields = nfields;
	table->sql_dict_list = sql_dict_list;
	for (j=0; j < nfields; j++)
	{
		MYSQL_FIELD *my_field = mysql_fetch_field_direct(res, j);
		ArrowField	*arrow_field = NULL;

		if (af_info)
			arrow_field = &af_info->footer.schema.fields[j];

		table->numBuffers +=
			mysql_setup_attribute(conn,
								  my_field,
								  arrow_field,
								  table,
								  &table->columns[j],
								  j+1);
		table->numFieldNodes++;
	}
	return table;
}

ssize_t
sqldb_fetch_results(void *sqldb_state, SQLtable *table)
{
	MYSTATE	   *mystate = (MYSTATE *)sqldb_state;
	MYSQL_ROW	row;

	if ((row = mysql_fetch_row(mystate->res)) != NULL)
	{
		unsigned long *row_sz = mysql_fetch_lengths(mystate->res);
		ssize_t		usage = 0;
		int			j;

		table->nitems++;
		for (j=0; j < table->nfields; j++)
		{
			SQLfield   *column = &table->columns[j];
			size_t		sz = (row[j] != NULL ? row_sz[j] : 0);

			usage += sql_field_put_value(column, row[j], sz);
			assert(table->nitems == column->nitems);
		}
		return usage;
	}
	return -1;
}

void
sqldb_close_connection(void *sqldb_state)
{
	MYSTATE	   *mystate = (MYSTATE *)sqldb_state;

	mysql_free_result(mystate->res);
	mysql_close(mystate->conn);
}

/*
 * misc functions
 */
void *
palloc(size_t sz)
{
	void   *ptr = malloc(sz);

	if (!ptr)
		Elog("out of memory");
	return ptr;
}

void *
palloc0(size_t sz)
{
	void   *ptr = malloc(sz);

	if (!ptr)
		Elog("out of memory");
	memset(ptr, 0, sz);
	return ptr;
}

char *
pstrdup(const char *str)
{
	char   *ptr = strdup(str);

	if (!ptr)
		Elog("out of memory");
	return ptr;
}

void *
repalloc(void *old, size_t sz)
{
	char   *ptr = realloc(old, sz);

	if (!ptr)
		Elog("out of memory");
	return ptr;
}

/*
 * PG12 or later replaces XXprintf by pg_XXprintf
 */
#ifdef vprintf
#undef vprintf
#endif
#ifdef vfprintf
#undef vfprintf
#endif
#ifdef vsprintf
#undef vsprintf
#endif
#ifdef vsnprintf
#undef vsnprintf
#endif

int
pg_printf(const char *fmt,...)
{
	va_list	args;
	int		r;

	va_start(args, fmt);
	r = vprintf(fmt, args);
	va_end(args);

	return r;
}

int
pg_fprintf(FILE *stream, const char *fmt,...)
{
	va_list args;
	int		r;

	va_start(args, fmt);
	r = vfprintf(stream, fmt, args);
    va_end(args);

	return r;
}

int
pg_sprintf(char *str, const char *fmt,...)
{
	va_list	args;
	int		r;

	va_start(args, fmt);
	r = vsprintf(str, fmt, args);
	va_end(args);

	return r;
}

int
pg_snprintf(char *str, size_t count, const char *fmt,...)
{
	va_list	args;
	int		r;

	va_start(args, fmt);
	r = vsnprintf(str, count, fmt, args);
	va_end(args);

	return r;
}

int
pg_vsnprintf(char *str, size_t count, const char *fmt, va_list args)
{
	return vsnprintf(str, count, fmt, args);
}
