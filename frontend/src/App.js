/* eslint-disable no-unused-vars */
import React, { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { useDropzone } from "react-dropzone";
import {
  RefreshCw,
  Zap,
  Disc,
  CloudOff,
  Loader,
  Trash2,
  Info,
} from "lucide-react";
import { Pie, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  Title,
  CategoryScale,
  LinearScale,
  BarElement,
} from "chart.js";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  Title,
  CategoryScale,
  LinearScale,
  BarElement
);

const API_BASE_URL = "http://localhost:8000";
const API_PREDICT_URL = `${API_BASE_URL}/predict`;
const API_HEALTH_URL = `${API_BASE_URL}/`;

const App = () => {
  const [results, setResults] = useState([]);
  const [backendStatus, setBackendStatus] = useState("Disconnected");
  const [isLoading, setIsLoading] = useState(false);
  const [processedPackets, setProcessedPackets] = useState(0);

  const checkBackendStatus = useCallback(async () => {
    try {
      const response = await axios.get(API_HEALTH_URL);
      if (response.status === 200) {
        setBackendStatus(`Connected (${response.data.model_status || "OK"})`);
      } else {
        setBackendStatus("Connected (Error)");
      }
    } catch {
      setBackendStatus("Disconnected (Check Python Server)");
    }
  }, []);

  const predictAnomaly = useCallback(
    async (packet) => {
      try {
        const response = await axios.post(API_PREDICT_URL, packet);
        const data = response.data;

        const isAnomaly =
          data.prediction === 1 || data.prediction === "Anomaly";
        const isSuspiciousBenign =
          !isAnomaly &&
          ((packet.length < 80 && packet.duration < 0.5) ||
            (packet.length > 1000 && packet.src_bytes > 10000));

        const explanation =
          data.explanation ||
          (isAnomaly
            ? "Abnormal traffic pattern — potential attack detected."
            : isSuspiciousBenign
            ? "Benign but inconsistent with normal thresholds."
            : "Normal behavior observed.");

        setResults((prev) => [
          {
            id: Date.now() + Math.random(),
            ...packet,
            prediction: isAnomaly
              ? "Malicious"
              : isSuspiciousBenign
              ? "Fishy"
              : "Benign",
            explanation,
            isAnomaly,
            isSuspiciousBenign,
          },
          ...prev.slice(0, 499),
        ]);
      } catch (err) {
        console.error("Prediction failed:", err);
      }
    },
    []
  );

  const handleDrop = useCallback(
    async (acceptedFiles) => {
      setIsLoading(true);
      setProcessedPackets(0);
      const file = acceptedFiles[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = async (e) => {
          const lines = e.target.result.trim().split("\n").slice(1);
          for (let i = 0; i < lines.length; i++) {
            const [protocol, length, duration, src_bytes, dst_bytes] =
              lines[i].split(",").map(Number);
            await predictAnomaly({
              protocol,
              length,
              duration,
              src_bytes,
              dst_bytes,
            });
            setProcessedPackets(i + 1);
          }
          setIsLoading(false);
        };
        reader.readAsText(file);
      } else setIsLoading(false);
    },
    [predictAnomaly]
  );

  const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
    onDrop: handleDrop,
    noClick: true,
    accept: { "text/csv": [".csv"] },
  });

  useEffect(() => {
    checkBackendStatus();
    const interval = setInterval(checkBackendStatus, 5000);
    return () => clearInterval(interval);
  }, [checkBackendStatus]);

  const benign = results.filter((r) => r.prediction === "Benign").length;
  const malicious = results.filter((r) => r.prediction === "Malicious").length;
  const fishy = results.filter((r) => r.prediction === "Fishy").length;

  const pieData = {
    labels: ["Benign", "Malicious", "Fishy"],
    datasets: [
      {
        data: [benign, malicious, fishy],
        backgroundColor: ["#22c55e", "#ef4444", "#facc15"],
      },
    ],
  };

  const protocols = [...new Set(results.map((r) => r.protocol))];
  const barData = {
    labels: protocols,
    datasets: [
      {
        label: "Packets per Protocol",
        data: protocols.map(
          (p) => results.filter((r) => r.protocol === p).length
        ),
        backgroundColor: "#3b82f6",
      },
    ],
  };

  return (
    <div className="min-h-screen p-6">
      <header className="flex justify-between items-center border-b pb-4">
        <h1 className="text-3xl font-bold">NIDS Anomaly Dashboard</h1>
        <button
          onClick={() => setResults([])}
          className="flex items-center bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700"
        >
          <Trash2 className="w-4 h-4 mr-1" /> Reset
        </button>
      </header>

      <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Panel */}
        <div
          {...getRootProps()}
          className={`border-2 border-dashed p-6 rounded-lg ${
            isDragActive ? "border-indigo-500" : "border-gray-300"
          }`}
        >
          <input {...getInputProps()} />
          <div className="text-center">
            <Disc className="mx-auto h-10 w-10 text-gray-400" />
            <p className="mt-2 text-sm">
              {isDragActive
                ? "Drop the CSV file here..."
                : "Drag or click to upload CSV"}
            </p>
            <button
              onClick={open}
              type="button"
              className="mt-3 bg-indigo-600 text-white px-4 py-2 rounded"
            >
              Browse File
            </button>
          </div>
          {isLoading && (
            <p className="mt-3 text-sm text-gray-500">
              Processing {processedPackets} records...
            </p>
          )}
        </div>

        {/* Right Panel */}
        <div className="lg:col-span-2 border rounded-lg shadow p-4">
          {/* Summary */}
          <div className="flex justify-between items-center mb-4">
            <div>
              <p>
                <b>Total:</b> {results.length} | <b>Benign:</b> {benign} |{" "}
                <b>Malicious:</b> {malicious} | <b>Fishy:</b> {fishy}
              </p>
            </div>
            <div className="w-36 h-36">
              <Pie data={pieData} />
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto max-h-[400px] border rounded">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="bg-gray-100">
                  <th className="px-4 py-2 text-left">Protocol</th>
                  <th className="px-4 py-2 text-left">Length</th>
                  <th className="px-4 py-2 text-left">Duration</th>
                  <th className="px-4 py-2 text-left">Src Bytes</th>
                  <th className="px-4 py-2 text-left">Result</th>
                </tr>
              </thead>
              <tbody>
                {results.length === 0 ? (
                  <tr>
                    <td
                      colSpan="5"
                      className="text-center py-3 text-gray-500 italic"
                    >
                      No results yet. Upload a CSV.
                    </td>
                  </tr>
                ) : (
                  results.map((r) => (
                    <tr
                      key={r.id}
                      className="border-t hover:bg-gray-50 transition"
                      title={r.explanation}
                    >
                      <td className="px-4 py-2">{r.protocol}</td>
                      <td className="px-4 py-2">{r.length}</td>
                      <td className="px-4 py-2">{r.duration}</td>
                      <td className="px-4 py-2">{r.src_bytes}</td>
                      <td
                        className={`px-4 py-2 font-semibold ${
                          r.prediction === "Malicious"
                            ? "text-red-600"
                            : r.prediction === "Fishy"
                            ? "text-yellow-600"
                            : "text-green-600"
                        }`}
                      >
                        {r.prediction}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Bar Graph */}
          <div className="mt-6">
            <h3 className="text-lg font-semibold mb-2">
              Protocol-Based Distribution
            </h3>
            <Bar data={barData} />
          </div>

          {/* Summary Below */}
          <div className="mt-6 p-4 border rounded-lg bg-gray-50">
            <h3 className="text-lg font-semibold mb-2">Analysis Summary</h3>
            <p className="text-sm text-gray-700">
              The model detected <b>{malicious}</b> malicious, <b>{fishy}</b>{" "}
              suspicious, and <b>{benign}</b> benign packets. Protocol-based
              activity shows how different traffic types are distributed. Hover
              over any record above to see why it was classified as benign,
              fishy, or malicious.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;
