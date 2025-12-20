/**
 * Normalizes a user-supplied name: trims it and capitalizes
 * the first letter while lowercasing the rest.
 * @param {string} name - raw name input from a form
 * @returns {string} the normalized name
 */
const normalizeName = (name) => {
	return name.trim().charAt(0).toUpperCase() + name.trim().slice(1).toLowerCase();
};

module.exports = { normalizeName };
