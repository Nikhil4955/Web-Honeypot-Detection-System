import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useUser } from '../context/UserContext';
import { formatApiErrorDetail } from '../utils/errorHandler';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';

const Register = () => {
  const navigate = useNavigate();
  const { register } = useUser();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await register(email, password, name);
      navigate('/dashboard');
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center bg-cover bg-center"
      style={{
        backgroundImage: 'url(https://images.pexels.com/photos/3612932/pexels-photo-3612932.jpeg)'
      }}
    >
      <div className="w-full max-w-md p-8 bg-black/60 backdrop-blur-xl border border-white/10 rounded-sm">
        <h1 className="text-4xl font-mono tracking-tight text-white mb-2" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          SOIN
        </h1>
        <p className="text-zinc-400 text-sm mb-8">Create your account</p>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <Label htmlFor="name" className="text-zinc-300 mb-2 block">
              Name
            </Label>
            <Input
              id="name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="register-name-input"
              className="w-full bg-zinc-900 border-zinc-700 text-white rounded-sm focus:ring-orange-500 focus:border-orange-500"
              required
            />
          </div>

          <div>
            <Label htmlFor="email" className="text-zinc-300 mb-2 block">
              Email
            </Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              data-testid="register-email-input"
              className="w-full bg-zinc-900 border-zinc-700 text-white rounded-sm focus:ring-orange-500 focus:border-orange-500"
              required
            />
          </div>

          <div>
            <Label htmlFor="password" className="text-zinc-300 mb-2 block">
              Password
            </Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              data-testid="register-password-input"
              className="w-full bg-zinc-900 border-zinc-700 text-white rounded-sm focus:ring-orange-500 focus:border-orange-500"
              required
            />
          </div>

          {error && (
            <div className="text-red-400 text-sm border border-red-500/30 bg-red-500/10 p-3 rounded-sm" data-testid="register-error-message">
              {error}
            </div>
          )}

          <Button
            type="submit"
            disabled={loading}
            data-testid="register-submit-button"
            className="w-full bg-orange-500 hover:bg-orange-600 text-white rounded-sm py-2 font-mono uppercase tracking-wide transition-colors"
          >
            {loading ? 'Creating account...' : 'Register'}
          </Button>
        </form>

        <p className="text-center text-zinc-400 text-sm mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-orange-500 hover:text-orange-400" data-testid="login-link">
            Login
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
