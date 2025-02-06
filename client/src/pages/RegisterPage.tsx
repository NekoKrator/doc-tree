import { Link } from 'react-router-dom'

function RegisterPage() {
    return (
        <div>
            <h1>Create Account</h1>
            <p>
                Already have an account?
                <Link to="/login">Log in here</Link>
            </p>
        </div>
    )
}

export default RegisterPage
