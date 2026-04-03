import { render, screen } from '@testing-library/react';
import App from './App';

test('renders phishing detector heading', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /detect phishing threats/i })).toBeInTheDocument();
});
