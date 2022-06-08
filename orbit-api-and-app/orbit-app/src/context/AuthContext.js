import React, { createContext, useContext, useEffect, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { publicFetch } from './../util/fetch'
import { FetchContext } from './FetchContext';

const AuthContext = createContext();
const { Provider } = AuthContext;

const AuthProvider = ({ children }) => {
	const history = useHistory();
	const fetchContext = useContext(FetchContext);

	const token = localStorage.getItem('token');
	const userInfo = localStorage.getItem('userInfo');
	const expiresAt = localStorage.getItem('expiresAt');

	const [authState, setAuthState] = useState({
		token,
		expiresAt,
		userInfo: userInfo ? JSON.parse(userInfo) : {}
	});

	useEffect(() => {
		const getUserInfo = async () => {
			try {
				const { data } = await fetchContext.authAxios.get(
					'/user-info'
				);
				setAuthState({
					userInfo: data.user,
					isAuthenticated: true
				});
			} catch (err) {
				setAuthState({
					userInfo: {},
					isAuthenticated: false
				});
			}
		};

		getUserInfo();
	}, [fetchContext]);

	const setAuthInfo = ({ token, userInfo, expiresAt }) => {
		localStorage.setItem('token', token);
		localStorage.setItem(
			'userInfo',
			JSON.stringify(userInfo)
		);
		localStorage.setItem('expiresAt', expiresAt);

		setAuthState({
			token,
			userInfo,
			expiresAt
		});
	};

	const logout = async () => {
		try {
			await publicFetch.delete('/token/invalidate')
			localStorage.removeItem('token');
			localStorage.removeItem('userInfo');
			localStorage.removeItem('expiresAt');
			setAuthState({});
			history.push('/login');
		} catch (error) {
			console.log(error);
		}
	};

	const isAuthenticated = () => {
		if (!authState.expiresAt) {
			return false;
		}
		return new Date() < new Date(authState.expiresAt);
	};


	const getAccessToken = () => {
		return localStorage.getItem("token");
	}

	const isAdmin = () => {
		return authState.userInfo.role === 'admin';
	};

	const getNewToken = async () => {
		try {
			const { data } = await publicFetch.get('/token/refresh');
			setAuthInfo(Object.assign({}, authState, { token: data.token }))
		} catch (error) {
			return error;
		}
	}

	const getNewTokenForRequest = async (failedRequest) => {
		const { data } = await publicFetch.get('/token/refresh');

		failedRequest.response.config.headers['Authorization'] = `Bearer ${data.token}`;

		localStorage.setItem('token', data.token);

		return Promise.resolve();
	}

	return (
		<Provider
			value={{
				authState,
				setAuthState: authInfo => setAuthInfo(authInfo),
				logout,
				isAuthenticated,
				isAdmin,
				getNewToken,
				getAccessToken,
				getNewTokenForRequest
			}}
		>
			{children}
		</Provider>
	);
};

export { AuthContext, AuthProvider };
