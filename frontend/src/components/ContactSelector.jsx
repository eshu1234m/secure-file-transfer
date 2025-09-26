import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = 'http://localhost:5000/api'; // Ensure this points to your backend

function ContactSelector({ accessToken, fileId }) {
  const [contacts, setContacts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedContact, setSelectedContact] = useState('');
  const [shareStatus, setShareStatus] = useState('');

  useEffect(() => {
    if (accessToken) {
      const fetchContacts = async () => {
        setLoading(true);
        try {
          // Pass the access token to the backend to fetch contacts
          const response = await axios.get(`${API_URL}/contacts`, {
            params: { access_token: accessToken },
          });
          setContacts(response.data);
          if (response.data.length > 0) {
            setSelectedContact(response.data[0].phone_number); // Pre-select first contact
          }
        } catch (error) {
          console.error('Error fetching contacts:', error);
          setShareStatus('Failed to load contacts. Please try signing in again.');
        } finally {
          setLoading(false);
        }
      };
      fetchContacts();
    }
  }, [accessToken]);

  const handleShareWithContact = async () => {
    if (!selectedContact || !fileId) {
      setShareStatus('Please select a contact and ensure a file is uploaded.');
      return;
    }
    setShareStatus('Sending SMS to contact...');
    try {
      const response = await axios.post(`${API_URL}/send`, {
        to_number: selectedContact,
        file_id: fileId,
      });
      setShareStatus(response.data.message);
    } catch (error) {
      console.error('Failed to send SMS to contact:', error);
      setShareStatus(error.response?.data?.error || 'Failed to send SMS.');
    }
  };

  if (loading) return <p>Loading contacts...</p>;
  if (contacts.length === 0 && accessToken) return <p>No mobile contacts found or permission denied.</p>;

  return (
    <div className="mt-3">
      {contacts.length > 0 && (
        <>
          <label htmlFor="contact-select" className="form-label">Select a contact:</label>
          <div className="input-group mb-3">
            <select
              id="contact-select"
              className="form-select"
              value={selectedContact}
              onChange={(e) => setSelectedContact(e.target.value)}
            >
              {contacts.map((contact, index) => (
                <option key={index} value={contact.phone_number}>
                  {contact.name} ({contact.phone_number})
                </option>
              ))}
            </select>
            <button className="btn btn-outline-primary" onClick={handleShareWithContact}>
              Send SMS
            </button>
          </div>
          {shareStatus && <div className="alert alert-info mt-2">{shareStatus}</div>}
        </>
      )}
    </div>
  );
}

export default ContactSelector;