import React, { useState } from 'react';
import axios from 'axios';
import Navbar from './Navbar';

const App = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [cveResults, setCVEResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSearch = async () => {
    if (!searchTerm) {
      setError('Please enter a search term');
      return;
    }

    if (!/^CVE-\d{4}-\d{4,7}$/.test(searchTerm)) {
      setError('Please enter a valid CVE ID (e.g., CVE-YYYY-NNNN)');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const response = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${searchTerm}`);
      const cveData = response.data.vulnerabilities;
      setCVEResults(cveData);
    } catch (error) {
      console.error('Error:', error);
      setError('An error occurred while fetching the data.');
    }

    setLoading(false);
  };

  const handleSaveResults = (cveId) => {
    // Check if there are results to save
    if (cveResults.length === 0) {
      return;
    }

    // Find the matching CVE result
    const matchingCve = cveResults.find((cve) => cve.cve.id === cveId);

    // Check if a matching CVE result is found
    if (matchingCve) {
      // Create a JSON blob of the result
      const jsonBlob = new Blob([JSON.stringify(matchingCve, null, 2)], { type: 'application/json' });

      // Create a temporary URL for the blob
      const url = URL.createObjectURL(jsonBlob);

      // Create a link element
      const link = document.createElement('a');
      link.href = url;
      link.download = `${matchingCve.cve.id}.json`;
      link.click();

      // Clean up the temporary URL
      URL.revokeObjectURL(url);
    }
  };

  return (
    <div>
      <Navbar />

      <div className="container mx-auto px-4 py-8">
        <div className="flex">
          <input
            type="text"
            placeholder="Search"
            className="w-full p-4 rounded-md border border-gray-300 focus:outline-none focus:border-indigo-500"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
          />

          <button
            className="px-6 py-3 ml-4 bg-indigo-500 text-white rounded-md font-bold"
            onClick={handleSearch}
            disabled={loading}
          >
            Search
          </button>
        </div>

        {error && <p className="mt-4 text-red-500">{error}</p>}

        {loading ? (
          <div className="text-center mt-8">
            <svg className="animate-spin h-8 w-8 mx-auto text-indigo-500" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 0 0 8 8V4a8 8 0 0 0-8 8zM4 12a8 8 0 0 1 8 8v-8a8 8 0 0 1-8 8z"
              />
            </svg>
            <p className="mt-2">Loading...</p>
          </div>
        ) : (
          <>
            {cveResults.length > 0 ? (
              <>
                {cveResults.map((cve) => (
                  <div key={cve.cve.id}>
                    <div className="flex justify-between mt-8">
                      <h2 className="text-2xl font-bold text-indigo-500">CVE: {cve.cve.id}</h2>
                      <button
                        className="px-6 py-3 mb-4 bg-indigo-500 text-white rounded-md font-bold"
                        onClick={() => handleSaveResults(cve.cve.id)}
                        disabled={cveResults.length === 0}
                      >
                        Save Results
                      </button>
                    </div>
                    <div className="bg-white rounded-lg shadow-md p-1 mt-1">
                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Source Identifier: </p>
                        <p className="text-1xl">{cve.cve.sourceIdentifier}</p>
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Published: </p>
                        <p className="text-1xl">{cve.cve.published}</p>
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Last Modified: </p>
                        <p className="text-1xl">{cve.cve.lastModified}</p>
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Vulnerability Status: </p>
                        <p className="text-1xl">{cve.cve.vulnStatus}</p>
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Descriptions: </p>
                        {cve.cve.descriptions.map((description, index) => (
                          <div key={index}>
                            <p>{description.lang}: {description.value}</p>
                          </div>
                        ))}
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Metrics: </p>
                        {Object.entries(cve.cve.metrics).map(([key, value]) => (
                          <div key={key} className="mt-2">
                            <p className="font-bold text-purple-500 text-2xl">{key}: </p>
                            {Array.isArray(value) ? (
                              <ul className="list-disc list-inside">
                                {value.map((item, index) => (
                                  <li key={index}>
                                    <p className="font-bold">Source: </p>
                                    {item.source}
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <p>{value}</p>
                            )}
                          </div>
                        ))}
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Weaknesses: </p>
                        {cve.cve.weaknesses.map((weakness, index) => (
                          <div key={index}>
                            <p>{weakness.source}: {weakness.type}</p>
                            {weakness.description.map((desc, descIndex) => (
                              <p key={descIndex}>- {desc.lang}: {desc.value}</p>
                            ))}
                          </div>
                        ))}
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Configurations: </p>
                        {cve.cve.configurations.map((configuration, index) => (
                          <div key={index}>
                            <p>Nodes:</p>
                            {configuration.nodes.map((node, nodeIndex) => (
                              <div key={nodeIndex}>
                                <p>Operator: {node.operator}</p>
                                <p>Negate: {node.negate ? 'true' : 'false'}</p>
                                <p>CPE Match:</p>
                                {node.cpeMatch.map((cpe, cpeIndex) => (
                                  <div key={cpeIndex}>
                                    <p>Vulnerable: {cpe.vulnerable ? 'true' : 'false'}</p>
                                    <p>Criteria: {cpe.criteria}</p>
                                    <p>Version End Including: {cpe.versionEndIncluding}</p>
                                    <p>Match Criteria ID: {cpe.matchCriteriaId}</p>
                                    <p>Version Start Including: {cpe.versionStartIncluding}</p>
                                    <p>Version Start Excluding: {cpe.versionStartExcluding}</p>
                                    <p>Version End Excluding: {cpe.versionEndExcluding}</p>
                                  </div>
                                ))}
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>

                      <div className="mt-4">
                        <p className="font-bold text-purple-500 text-2xl">Impact: </p>
                        {cve.cve.impact && Object.entries(cve.cve.impact).map(([key, value]) => (
                          <div key={key} className="mt-2">
                            <p className="font-bold text-purple-500 text-2xl">{key}: </p>
                            {Array.isArray(value) ? (
                              <ul className="list-disc list-inside">
                                {value.map((item, index) => (
                                  <li key={index}>
                                    <p className="font-bold">Source: </p>
                                    {item.source}
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <p>{value}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <p className="mt-4 text-gray-600">No results found.</p>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default App;
