import React from "react";
import { AlertTriangle } from "lucide-react";

// A page that fails to draw shows a plain message with a way out, never a blank screen.
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch() {
    // Nothing is sent anywhere; the message below is all the visitor needs.
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return <div className="alert alert-error" role="alert" data-testid="page-error">
      <AlertTriangle size={18} />
      <div><strong>This part of the page could not be shown</strong><span>Your data is safe. Please reload the page, or go back and open it again.</span></div>
      <button className="alert-action" onClick={() => this.setState({ failed: false })}>Try again</button>
    </div>;
  }
}
