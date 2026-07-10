import React, { Component } from 'react'
import Login from './components/login/login'
import ChatWindow from "./components/chatWindow/chatWindow";
import { createSignalProtocolManager } from "./services/signal-gateway"

import './App.css';
export default class ChatApp extends Component {
  constructor(props) {
    super(props)
    this.state = {
      isLoggedIn: false,
      loggedInUserObj: {},
      signalProtocolManagerUser: undefined
    }
    this.setLoggedinUser = this.setLoggedinUser.bind(this)
  }

  setLoggedinUser(loggedInUserObj) {
    this.setState({ isLoggedIn: true, loggedInUserObj: { ...loggedInUserObj } }, () => {
      createSignalProtocolManager(loggedInUserObj._id, loggedInUserObj.name)
        .then(signalProtocolManagerUser => {
          this.setState({ signalProtocolManagerUser: signalProtocolManagerUser })
        })
    })
  }

  render() {

    // ChatWindow only mounts once the signal manager is ready: it opens the
    // WebSocket in componentDidMount, and a message arriving before the
    // manager exists could not be decrypted (it would be silently lost).
    return (
      <div className="App">
        { !this.state.isLoggedIn && <Login loginProp={this.setLoggedinUser} />}
        { this.state.isLoggedIn && this.state.signalProtocolManagerUser && <ChatWindow
          loggedInUserObj={this.state.loggedInUserObj}
          signalProtocolManagerUser={this.state.signalProtocolManagerUser}
        />}
      </div>
    )
  }
}
