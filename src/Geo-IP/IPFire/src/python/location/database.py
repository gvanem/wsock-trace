"""
	A lightweight wrapper around psycopg3.
"""

import asyncio
import logging
import psycopg
import psycopg_pool
import time

# Setup logging
log = logging.getLogger("location.database")

class Connection(object):
	def __init__(self, host, database, user=None, password=None):
		# Stores connections assigned to tasks
		self.__connections = {}

		# Create a connection pool
		self.pool = psycopg_pool.ConnectionPool(
			"postgresql://%s:%s@%s/%s" % (user, password, host, database),

			# Callback to configure any new connections
			configure=self.__configure,

			# Set limits for min/max connections in the pool
			min_size=1,
			max_size=512,

			# Give clients up to one minute to retrieve a connection
			timeout=60,

			# Close connections after they have been idle for a few seconds
			max_idle=5,
		)

	def __configure(self, conn):
		"""
			Configures any newly opened connections
		"""
		# Enable autocommit
		conn.autocommit = True

		# Return any rows as dicts
		conn.row_factory = psycopg.rows.dict_row

	def connection(self, *args, **kwargs):
		"""
			Returns a connection from the pool
		"""
		# Fetch the current task
		task = asyncio.current_task()

		assert task, "Could not determine task"

		# Try returning the same connection to the same task
		try:
			return self.__connections[task]
		except KeyError:
			pass

		# Fetch a new connection from the pool
		conn = self.__connections[task] = self.pool.getconn(*args, **kwargs)

		log.debug("Assigning database connection %s to %s" % (conn, task))

		# When the task finishes, release the connection
		task.add_done_callback(self.__release_connection)

		return conn

	def __release_connection(self, task):
		# Retrieve the connection
		try:
			conn = self.__connections[task]
		except KeyError:
			return

		log.debug("Releasing database connection %s of %s" % (conn, task))

		# Delete it
		del self.__connections[task]

		# Return the connection back into the pool
		self.pool.putconn(conn)

	def _execute(self, cursor, execute, query, parameters):
		# Store the time we started this query
		#t = time.monotonic()

		#try:
		#	log.debug("Running SQL query %s" % (query % parameters))
		#except Exception:
		#	pass

		# Execute the query
		execute(query, parameters)

		# How long did this take?
		#elapsed = time.monotonic() - t

		# Log the query time
		#log.debug("  Query time: %.2fms" % (elapsed * 1000))

	def query(self, query, *parameters, **kwparameters):
		"""
			Returns a row list for the given query and parameters.
		"""
		conn = self.connection()

		with conn.cursor() as cursor:
			self._execute(cursor, cursor.execute, query, parameters or kwparameters)

			return [Row(row) for row in cursor]

	def get(self, query, *parameters, **kwparameters):
		"""
			Returns the first row returned for the given query.
		"""
		rows = self.query(query, *parameters, **kwparameters)
		if not rows:
			return None
		elif len(rows) > 1:
			raise Exception("Multiple rows returned for Database.get() query")
		else:
			return rows[0]

	def execute(self, query, *parameters, **kwparameters):
		"""
			Executes the given query.
		"""
		conn = self.connection()

		with conn.cursor() as cursor:
			self._execute(cursor, cursor.execute, query, parameters or kwparameters)

	def executemany(self, query, parameters):
		"""
			Executes the given query against all the given param sequences.
		"""
		conn = self.connection()

		with conn.cursor() as cursor:
			self._execute(cursor, cursor.executemany, query, parameters)

	def transaction(self):
		"""
			Creates a new transaction on the current tasks' connection
		"""
		conn = self.connection()

		return conn.transaction()

	def pipeline(self):
		"""
			Sets the connection into pipeline mode.
		"""
		conn = self.connection()

		return conn.pipeline()


class Row(dict):
	"""A dict that allows for object-like property access syntax."""
	def __getattr__(self, name):
		try:
			return self[name]
		except KeyError:
			raise AttributeError(name)
